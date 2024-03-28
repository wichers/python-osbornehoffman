import asyncio
import base64
import logging
import re
from collections.abc import Awaitable, Callable
from datetime import datetime
from enum import Enum

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from crc import Calculator, Crc16

from .account import OHAccount
from .tables import CID_SIA_MAPPING, SIA_EVENTS

_LOGGER = logging.getLogger(__name__)

# Security Industry Association event parsing
sia_parse_regex = r"""\n01010[0-9a-fA-F]{3}.SIA-DCS.
(?P<sequence>[0-9a-fA-F]{4})R
(?P<receiver>[0-9a-fA-F]{4})L
(?P<line>[0-9a-fA-F]{4,5})\[\#
(?P<account>[0-9a-fA-F]{6})\|
(?P<qualifier>.)?r?i?
(?P<area>[0-9a-fA-F]{1,4})?\/?
(?P<event_code>(
    (?P<sia_event>[a-zA-Z]{2})
    (?P<sia_code>[0-9a-fA-F]{0,4})?\/?)+)
(\*\'(?P<text>.*)\'NM)?\]
(?P<panel_id>[0-9a-fA-F]{16})?(\|\#)?
(?P<system_account>[0-9a-fA-F]{6})?(?:T)?
(?P<timestamp>[0-9a-fA-F]{8})?\r.*"""
SIA_MATCHER = re.compile(sia_parse_regex, re.X)

# Contact ID event parsing
cid_parse_regex = r"""\n01010[0-9a-fA-F]{3}.ADM-CID.
(?P<sequence>[0-9a-fA-F]{4})R
(?P<receiver>[0-9a-fA-F]{4})L
(?P<line>[0-9a-fA-F]{4,5})\[\#
(?P<account>[0-9a-fA-F]{6})\|
(?P<qualifier>[0-9a-fA-F]{1})
(?P<event_code>[0-9a-fA-F]{3})[\s]
(?P<area>[0-9a-fA-F]{2})[\s]
(?P<zone>[0-9a-fA-F]{3})\]
((?P<panel_id>[0-9a-fA-F]{16})\|\#
(?P<system_account>[0-9a-fA-F]{6}))?(?:T)?
(?P<timestamp>[0-9a-fA-F]{8})?\r.*"""
CID_MATCHER = re.compile(cid_parse_regex, re.X)

# V2 and higher heartbeat
hb_v2_parse_regex = r"""SR
(?P<receiver>[0-9a-fA-F]{4})L
(?P<line>[0-9a-fA-F]{4,5})[\s]{4}
(?P<system_account>[0-9a-fA-F]{6})XX[\s]{4}\x00\[ID
(?P<panel_id>[0-9a-fA-F]{8})\]\s?(?:T)?
(?P<timestamp>[0-9a-fA-F]{8})?[\S\s]*"""
HB_V2_MATCHER = re.compile(hb_v2_parse_regex, re.X)

# <= 1.93 heartbeat
hb_v1_parse_regex = r"""SR
(?P<receiver>[0-9a-fA-F]{4})L
(?P<line>[0-9a-fA-F]{4,5})[\s]{4}
(?P<system_account>[0-9a-fA-F]{6})XX[\s]{4}[\S\s]*"""
HB_V1_MATCHER = re.compile(hb_v1_parse_regex, re.X)

v4_header_parse_regex = r"""\#40R
(?P<receiver>[0-9a-fA-F]{4})L
(?P<line>[0-9a-fA-F]{4,5})A
(?P<system_account>[0-9a-fA-F]{6})S
(?P<payload_length>[0-9a-fA-F]{4})
(?P<panel_iv>[\S\s]{16})[\S\s]*C
(?P<crc>[0-9a-fA-F]{4})"""
V4_HEADER_MATCHER = re.compile(v4_header_parse_regex, re.X)


class MessageType(Enum):
    SIA = 1
    CID = 2
    HB_V1 = 3
    HB_V2 = 4


class OHConnection:

    def __init__(self, server):
        """Initialize the instance."""
        self._server = server
        self._key = DES3.adjust_key_parity(get_random_bytes(24))
        self._cipher = DES3.new(self._key, mode=DES3.MODE_ECB)

    async def __call__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Process callback from the TCP server if a new connection has been
        opened."""
        peername = writer.get_extra_info("peername")

        _LOGGER.debug("Sending key handshake to panel")
        writer.write(self.get_scrambled_key())
        await writer.drain()

        while not reader.at_eof():
            try:
                data = await reader.read(1024)
                if data is None:
                    break
            except asyncio.IncompleteReadError:
                continue
            except ConnectionResetError:
                break

            try:
                event = await self.parse_event(peername, data)
            except ValueError as exc:
                _LOGGER.warning("Formatting error: %s, %s", exc, data)
                continue
            except NotImplementedError as exc:
                _LOGGER.warning("%s: %s", exc, data)
                continue

            if self._server.accounts:
                account = self._server.accounts.get(event.get("system_account"))

            if account is None:
                _LOGGER.warning("Received event for non existing account: %s", event)
                continue

            # New panel ID requested?
            if (
                event.get("message_type") in (MessageType.HB_V2, MessageType.HB_V1)
                and event.get("panel_id") != account.panel_id
            ):
                # the panel ID is used to check for Panel Substition which
                # should trigger an AA Alarm on the server:
                # AA Alarm - Panel Substitution An attempt to substitute an
                # alternate alarm panel for a secure panel has been made
                _LOGGER.debug("Sending new ID (%d) to panel", account.panel_id)
                response = b"ID" + str(account.panel_id).zfill(8).encode()
                response = self.encrypt_data(response)
            else:

                if (
                    event.get("message_type") in (MessageType.HB_V2, MessageType.HB_V1)
                    and account.forward_hearbeat is False
                ):
                    ack = True
                elif self._server.callback is not None:
                    ack = await self._server.callback(event)
                else:
                    ack = True

                _LOGGER.debug(
                    "Acknowledge: %s, Encrypted: %s", ack, event.get("encrypted_ack")
                )
                response = self.get_ack_response(ack, event.get("encrypted_ack"))

            writer.write(response)
            await writer.drain()

    def get_ack_response(self, ack, encrypted):
        if encrypted:
            if ack:
                response = b"ACK\r"
            else:
                response = b"NACK\r"
            response = self.encrypt_data(response)
        else:
            if ack:
                response = b"ACK\r\n"
            else:
                response = b"NACK\r\n"
        return response

    async def parse_event(self, peername: tuple, data: bytes) -> dict:
        event = {"peername": peername}

        data = self.decrypt_data(data)
        _LOGGER.debug("Decrypted data: %s", data)

        # we regex on string not on bytearray
        data = data.decode("ascii")

        if sia_match := SIA_MATCHER.match(data):
            event |= sia_match.groupdict()
            event["message_type"] = MessageType.SIA

            if event.get("system_account") is None:
                event["system_account"] = event.get("account")

            msglen = data.find("]") + 1

        elif cid_match := CID_MATCHER.match(data):
            event |= cid_match.groupdict()
            event["message_type"] = MessageType.CID

            if event.get("system_account") is None:
                event["system_account"] = event.get("account")

            # If it is a ADM-CID message, map the qualifier and type to a code.
            if (
                event.get("qualifier") is not None
                and event.get("event_code") is not None
            ):
                sub_map = CID_SIA_MAPPING.get(event["event_code"])
                if sub_map and sub_map.get(event["qualifier"]) is not None:
                    event["sia_event"] = sub_map[event["qualifier"]]

            msglen = data.find("]") + 1

        elif hb_match := HB_V2_MATCHER.match(data):
            event |= hb_match.groupdict()
            event["message_type"] = MessageType.HB_V2

            msglen = data.find("XX") + 2

        elif hb_match := HB_V1_MATCHER.match(data):
            event |= hb_match.groupdict()
            event["message_type"] = MessageType.HB_V1

            msglen = data.find("XX") + 2

        elif v4_match := V4_HEADER_MATCHER.match(data):
            event |= v4_match.groupdict()
            event["payload_length"] = int(event["payload_length"], 16)
            event["crc"] = int(event["crc"], 16)
            calc = Calculator(Crc16.MODBUS)
            crc = calc.checksum(data[: event["payload_length"] + 41])
            if event["crc"] != crc:
                raise NotImplementedError("v4 crc mismatch on payload")

        else:
            raise NotImplementedError(
                "No matches found, event was not an OH Spec event"
            )

        event["encrypted_ack"] = (len(data) % 8 == 0) and (
            data.count("\x00", msglen - 1) > 0
        )

        if panel_id := event.get("panel_id"):
            if len(panel_id) == 16:
                panel_id = base64.b16decode(panel_id)
                panel_id = self.decrypt_data(panel_id).decode()
            event["panel_id"] = int(panel_id, 16)

        if event.get("timestamp") is not None:
            timestamp = int(event["timestamp"], 16)
            event["timestamp"] = datetime.fromtimestamp(timestamp).isoformat()

        # If there is an event, map it to the SIA Code spec.
        if event.get("sia_event") is not None and (
            sub_map := SIA_EVENTS.get(event["sia_event"])
        ):
            event["sia_type"] = sub_map.get("type")
            event["sia_description"] = sub_map.get("description")
            event["sia_concerns"] = sub_map.get("concerns")

        _LOGGER.debug("Event: %s", event)

        return event

    def encrypt_data(
        self,
        data: bytes,
    ):
        block_size = 8
        padding_len = block_size - len(data) % block_size
        padding = bytearray(chr(0) * (padding_len), "ascii")
        data += padding
        data = self._cipher.encrypt(data)
        return data

    def decrypt_data(
        self,
        data: bytes,
    ):
        data = self._cipher.decrypt(data[: len(data) - len(data) % 8])
        return data

    def get_scrambled_key(self):
        key = bytearray(self._key)
        key[0] ^= 0x55
        key[1] ^= 0x2D
        key[2] ^= 0x6A
        key[3] ^= 0x05
        key[4] ^= 0x23
        key[5] ^= 0x49
        key[6] ^= 0x39
        key[7] ^= 0xA8
        key[8] ^= 0x45
        key[9] ^= 0x29
        key[10] ^= 0xD3
        key[11] ^= 0xE9
        key[12] ^= 0x94
        key[13] ^= 0xC2
        key[14] ^= 0xB5
        key[15] ^= 0x88
        key[16] ^= 0x45
        key[17] ^= 0xA3
        key[18] ^= 0x50
        key[19] ^= 0x8A
        key[20] ^= 0x44
        key[21] ^= 0xAA
        key[22] ^= 0x69
        key[23] ^= 0x54
        return key


class OHServer:
    """Manages TCP server for Osborne Hoffman compatible <= V3 devices.

    Opens a single port and listens for incoming TCP connections.
    """

    def __init__(
        self,
        host: str,
        port: int,
        accounts: dict[str, OHAccount],
        callback: Callable[[dict], Awaitable[bool]] | None = None,
    ) -> None:
        """Initialize instance."""
        self.host = host
        self.port = port
        self.accounts = accounts
        self.callback = callback
        self.server = None

    async def start_server(self):
        """Start TCP server on configured port."""
        self.server = await asyncio.start_server(
            OHConnection(self), host=self.host, port=self.port
        )

    async def close_server(self):
        """Close TCP server."""
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
