"""Osborne Hoffman protocol server implementation.

Supports V1-V3 (3DES/ECB) and V4 (AES/CBC with Diffie-Hellman key exchange).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
from collections.abc import Awaitable, Callable
from datetime import datetime
from enum import Enum

from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from crc import Calculator, Crc16

from .account import OHAccount
from .tables import CID_SIA_MAPPING, SIA_EVENTS

_LOGGER = logging.getLogger(__name__)

# XOR mask for key scrambling (OH protocol spec)
_KEY_XOR_MASK = bytes([
    0x55, 0x2D, 0x6A, 0x05, 0x23, 0x49, 0x39, 0xA8,
    0x45, 0x29, 0xD3, 0xE9, 0x94, 0xC2, 0xB5, 0x88,
    0x45, 0xA3, 0x50, 0x8A, 0x44, 0xAA, 0x69, 0x54,
])

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
    (?P<sia_zone>[0-9a-fA-F]{0,4})?\/?)+)
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
(?P<panel_id>[0-9a-fA-F]{16})?(\|\#)?
(?P<system_account>[0-9a-fA-F]{6})?(?:T)?
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

# V4 protocol header (checked on raw bytes BEFORE 3DES decryption)
v4_header_parse_regex = r"""\#40R
(?P<receiver>[0-9a-fA-F]{4})L
(?P<line>[0-9a-fA-F]{4,5})A
(?P<system_account>[0-9a-fA-F]{6})S
(?P<payload_length>[0-9a-fA-F]{4})"""
V4_HEADER_MATCHER = re.compile(v4_header_parse_regex, re.X)

# V4 header constants
V4_HEADER_LEN = 25       # Header without IV
V4_HEADER_IV_LEN = 41    # Header + 16-byte IV
V4_IV_LEN = 16           # IV length
V4_CRC_FIELD_LEN = 5     # "C" + 4 hex chars


class MessageType(Enum):
    SIA = 1
    CID = 2
    HB_V1 = 3
    HB_V2 = 4
    DHR = 5
    V4 = 6


class OHConnection:

    def __init__(self, server: "OHServer") -> None:
        """Initialize the instance with per-connection 3DES key."""
        self._server = server
        self._key = DES3.adjust_key_parity(get_random_bytes(24))
        self._cipher = DES3.new(self._key, mode=DES3.MODE_ECB)
        self._scrambled_key = self._scramble_key(self._key)
        # Server IV for V4: first 16 bytes of the scrambled key
        self._server_iv = bytes(self._scrambled_key[:V4_IV_LEN])
        # Per-connection AES key (set after DH negotiation or from keystore)
        self._aes_key: bytes | None = None
        # Last mixed IV for V4 AES encryption (updated per V4 message)
        self._mixed_iv: bytes | None = None
        # Last known account for this connection (needed for DHR which has no account field)
        self._last_account: OHAccount | None = None

    async def __call__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Process callback from the TCP server when a new connection is opened."""
        peername = writer.get_extra_info("peername")
        _LOGGER.debug("New connection from %s", peername)

        try:
            _LOGGER.debug("Sending key handshake to panel")
            writer.write(self._scrambled_key)
            await writer.drain()

            while not reader.at_eof():
                try:
                    data = await asyncio.wait_for(
                        reader.read(1024), timeout=300
                    )
                    if not data:
                        break
                except asyncio.TimeoutError:
                    _LOGGER.debug("Connection timeout for %s", peername)
                    break
                except asyncio.IncompleteReadError:
                    continue
                except ConnectionResetError:
                    break

                # Check for V4 header BEFORE 3DES decryption
                # V4 messages have a plaintext header, not 3DES encrypted
                is_v4, event = await self._process_message(
                    peername, data, reader, writer
                )
                if event is None:
                    if is_v4:
                        # V4 message couldn't be processed; send 3DES NACK
                        writer.write(self._encrypt_des3(b"NACK\r"))
                        await writer.drain()
                    continue

                # Handle DHR — Diffie-Hellman request (V4 setup)
                # DHR has no system_account; use last known account
                if event.get("message_type") == MessageType.DHR:
                    if self._last_account is None:
                        _LOGGER.warning(
                            "DHR received before any account identified"
                        )
                        continue
                    await self._handle_dhr(
                        event, self._last_account, reader, writer
                    )
                    continue

                account = self._resolve_account(event)

                if account is None:
                    _LOGGER.warning(
                        "Received event for non existing account: %s", event
                    )
                    continue

                self._last_account = account

                # Panel ID assignment (V2+ only — V1 has no panel_id field)
                if (
                    event.get("message_type") == MessageType.HB_V2
                    and event.get("panel_id") != account.panel_id
                ):
                    _LOGGER.debug(
                        "Sending new ID (%08X) to panel", account.panel_id
                    )
                    id_response = b"ID" + f"{account.panel_id:08X}".encode()
                    if is_v4:
                        id_response = self._encrypt_aes(id_response)
                    else:
                        id_response = self._encrypt_des3(id_response)
                    writer.write(id_response)
                    await writer.drain()

                # Invoke callback (unless heartbeat with forward_heartbeat=False)
                if (
                    event.get("message_type")
                    in (MessageType.HB_V2, MessageType.HB_V1)
                    and account.forward_heartbeat is False
                ):
                    ack = True
                elif self._server.callback is not None:
                    ack = await self._server.callback(event)
                else:
                    ack = True

                _LOGGER.debug(
                    "Acknowledge: %s, Encrypted: %s, V4: %s",
                    ack,
                    event.get("encrypted_ack"),
                    is_v4,
                )
                response = self._get_ack_response(
                    ack, event.get("encrypted_ack"), is_v4
                )
                writer.write(response)
                await writer.drain()
        finally:
            _LOGGER.debug("Closing connection from %s", peername)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_message(
        self,
        peername: tuple,
        data: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> tuple[bool, dict | None]:
        """Process an incoming message, detecting V4 vs V3 format.

        Returns (is_v4, event_dict) or (False, None) on error.
        """
        # Try to detect V4 header on raw (un-decrypted) data
        try:
            raw_str = data[:V4_HEADER_LEN].decode("ascii", errors="ignore")
        except Exception:
            raw_str = ""

        if raw_str.startswith("#40"):
            return await self._process_v4_message(peername, data)

        # V3 and below: decrypt with 3DES first
        try:
            event = self._parse_v3_event(peername, data)
        except ValueError as exc:
            _LOGGER.warning("Formatting error: %s, %s", exc, data)
            return False, None
        except NotImplementedError as exc:
            _LOGGER.warning("%s: %s", exc, data)
            return False, None

        return False, event

    async def _process_v4_message(
        self, peername: tuple, data: bytes
    ) -> tuple[bool, dict | None]:
        """Process a V4 protocol message (AES/CBC encrypted payload)."""
        try:
            data_str = data.decode("ascii", errors="ignore")
        except Exception:
            _LOGGER.warning("V4: Failed to decode header")
            return True, None

        v4_match = V4_HEADER_MATCHER.match(data_str)
        if not v4_match:
            _LOGGER.warning("V4: Header pattern match failed")
            return True, None

        header_fields = v4_match.groupdict()
        payload_length = int(header_fields["payload_length"], 16)
        system_account = header_fields["system_account"]

        # Extract panel IV (16 bytes after the 25-byte header)
        if len(data) < V4_HEADER_IV_LEN + payload_length + V4_CRC_FIELD_LEN:
            _LOGGER.warning("V4: Message too short")
            return True, None

        panel_iv = data[V4_HEADER_LEN:V4_HEADER_IV_LEN]

        # CRC validation over header + payload
        # Extract CRC from raw bytes (not data_str, which drops non-ASCII bytes)
        crc_offset = V4_HEADER_IV_LEN + payload_length
        crc_field = data[crc_offset : crc_offset + V4_CRC_FIELD_LEN]
        try:
            if crc_field[0:1] != b"C":
                raise ValueError(f"Expected 'C' prefix, got {crc_field[0:1]!r}")
            msg_crc = int(crc_field[1:].decode("ascii"), 16)
        except (ValueError, UnicodeDecodeError) as exc:
            _LOGGER.warning("V4: Invalid CRC field: %s (%s)", crc_field, exc)
            return True, None

        calc = Calculator(Crc16.MODBUS)
        calc_crc = calc.checksum(data[: payload_length + V4_HEADER_IV_LEN])
        if msg_crc != calc_crc:
            _LOGGER.warning(
                "V4: CRC mismatch (got %04X, expected %04X)", msg_crc, calc_crc
            )
            return True, None

        # Get AES key for this account
        aes_key = self._get_aes_key(system_account)
        if aes_key is None:
            _LOGGER.warning(
                "V4: No AES key for account %s", system_account
            )
            return True, None

        # Mix IVs: even indices from server, odd indices from panel
        # Store mixed IV for the response encryption (Java uses same mixed IV)
        mixed_iv = self._mix_iv(panel_iv)
        self._mixed_iv = mixed_iv

        # Decrypt payload with AES/CBC
        encrypted_payload = data[
            V4_HEADER_IV_LEN : V4_HEADER_IV_LEN + payload_length
        ]
        # Ensure payload is multiple of AES block size
        if len(encrypted_payload) % 16 != 0:
            _LOGGER.warning("V4: Payload not aligned to AES block size")
            return True, None

        try:
            cipher = AES.new(aes_key, AES.MODE_CBC, mixed_iv)
            decrypted = cipher.decrypt(encrypted_payload)
        except Exception as exc:
            _LOGGER.warning("V4: AES decryption failed: %s", exc)
            return True, None

        _LOGGER.debug("V4 decrypted payload: %s", decrypted)

        # Parse decrypted payload as a V3-style message
        try:
            decrypted_str = decrypted.decode("ascii", errors="ignore")
        except Exception:
            _LOGGER.warning("V4: Failed to decode decrypted payload")
            return True, None

        # Parse the decrypted inner message
        event = {"peername": peername, "is_v4": True}
        event = self._parse_message_content(event, decrypted_str)

        if event is None:
            _LOGGER.warning("V4: Failed to parse decrypted payload")
            return True, None

        # V4: always use system_account from header (authoritative)
        event["system_account"] = system_account

        # Store V4 metadata
        event["panel_iv"] = panel_iv

        _LOGGER.debug("V4 Event: %s", event)
        return True, event

    def _parse_v3_event(self, peername: tuple, data: bytes) -> dict:
        """Parse a V3 (3DES-encrypted) message."""
        decrypted = self._decrypt_des3(data)
        _LOGGER.debug("Decrypted data: %s", decrypted)

        decoded = decrypted.decode("ascii", errors="ignore")

        # Check for DHR (Diffie-Hellman Request)
        if decoded.strip("\x00").startswith("DHR"):
            return {
                "peername": peername,
                "message_type": MessageType.DHR,
                "system_account": None,
                "encrypted_ack": False,
            }

        event = {"peername": peername}
        event = self._parse_message_content(event, decoded)

        if event is None:
            raise NotImplementedError(
                "No matches found, event was not an OH Spec event"
            )

        _LOGGER.debug("Event: %s", event)
        return event

    def _parse_message_content(
        self, event: dict, data: str
    ) -> dict | None:
        """Parse decoded message content against SIA/CID/HB patterns.

        Returns the enriched event dict, or None if no pattern matched.
        """
        msglen = 0

        if sia_match := SIA_MATCHER.match(data):
            event |= sia_match.groupdict()
            event["message_type"] = MessageType.SIA
            msglen = data.find("]") + 1

        elif cid_match := CID_MATCHER.match(data):
            event |= cid_match.groupdict()
            event["message_type"] = MessageType.CID

            # Map CID qualifier+type to SIA code
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

        else:
            return None

        # Determine if ACK should be encrypted
        event["encrypted_ack"] = (len(data) % 8 == 0) and (
            data.count("\x00", msglen - 1) > 0
        )

        # Decrypt panel ID if encrypted (16-char hex = encrypted, 8-char = plain)
        if panel_id := event.get("panel_id"):
            try:
                if len(panel_id) == 16:
                    panel_id = base64.b16decode(panel_id)
                    panel_id = self._decrypt_des3(panel_id).decode(
                        "ascii", errors="ignore"
                    ).strip("\x00")
                event["panel_id"] = int(panel_id, 16)
            except (ValueError, Exception) as exc:
                _LOGGER.warning("Failed to parse panel_id '%s': %s", panel_id, exc)
                event["panel_id"] = None

        # Convert timestamp from hex epoch to ISO format
        if event.get("timestamp") is not None:
            try:
                timestamp = int(event["timestamp"], 16)
                event["timestamp"] = datetime.fromtimestamp(
                    timestamp
                ).isoformat()
            except (ValueError, OSError):
                _LOGGER.warning(
                    "Invalid timestamp: %s", event["timestamp"]
                )
                event["timestamp"] = None

        # Map SIA event code to full spec description
        if event.get("sia_event") is not None and (
            sub_map := SIA_EVENTS.get(event["sia_event"])
        ):
            event["sia_type"] = sub_map.get("type")
            event["sia_description"] = sub_map.get("description")
            event["sia_concerns"] = sub_map.get("concerns")

        return event

    def _resolve_account(self, event: dict) -> OHAccount | None:
        """Resolve event to a registered account.

        Tries in order:
        1. system_account field (primary key from message suffix or V4 header)
        2. account field (subscriber account, may match system_account)
        3. Last known account on this connection (session state)
        4. Single-account fallback (only one account configured)

        Also sets event["system_account"] to the resolved account_id when
        resolved via fallback, so downstream code has a consistent value.
        """
        accounts = self._server.accounts
        if not accounts:
            return None

        # Try system_account (from |#XXXXXX suffix or V4 header)
        if sa := event.get("system_account"):
            if acct := accounts.get(sa):
                return acct

        # Try account field (inside [] brackets — matches when account == system_account)
        if a := event.get("account"):
            if acct := accounts.get(a):
                event["system_account"] = acct.account_id
                return acct

        # Fall back to last known account on this connection
        # (panels send heartbeat first, then SIA/CID on same connection)
        if self._last_account is not None:
            event["system_account"] = self._last_account.account_id
            return self._last_account

        # Single-account fallback (common in Home Assistant deployments)
        if len(accounts) == 1:
            acct = next(iter(accounts.values()))
            event["system_account"] = acct.account_id
            return acct

        return None

    async def _handle_dhr(
        self,
        event: dict,
        account: OHAccount,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a Diffie-Hellman key exchange request from the panel."""
        from .dh import negotiate_dh

        _LOGGER.info("DHR: Starting Diffie-Hellman negotiation")
        aes_key = await negotiate_dh(reader, writer)

        if aes_key is None:
            _LOGGER.warning("DHR: Key exchange failed")
            return

        # Store the negotiated AES key
        self._aes_key = aes_key
        if self._server.keystore is not None:
            self._server.keystore.store_aes_key(
                account.account_id, aes_key
            )
        _LOGGER.info("DHR: AES key negotiated for account %s", account.account_id)

    def _get_aes_key(self, system_account: str) -> bytes | None:
        """Look up the AES key for a system account."""
        # First check connection-local key
        if self._aes_key is not None:
            return self._aes_key
        # Then check the server keystore
        if self._server.keystore is not None:
            return self._server.keystore.get_aes_key(system_account)
        return None

    def _mix_iv(self, panel_iv: bytes) -> bytes:
        """Mix server and panel IVs per OH V4 spec.

        Even byte indices come from the server IV,
        odd byte indices come from the panel IV.
        """
        mixed = bytearray(V4_IV_LEN)
        for i in range(V4_IV_LEN):
            mixed[i] = self._server_iv[i] if i % 2 == 0 else panel_iv[i]
        return bytes(mixed)

    def _get_ack_response(
        self, ack: bool, encrypted: bool, is_v4: bool = False
    ) -> bytes:
        """Construct ACK/NACK response with appropriate encryption."""
        if is_v4:
            # V4: AES-encrypted 16-byte response
            response = b"ACK\r" if ack else b"NACK\r"
            return self._encrypt_aes(response)
        if encrypted:
            response = b"ACK\r" if ack else b"NACK\r"
            return self._encrypt_des3(response)
        return b"ACK\r\n" if ack else b"NACK\r\n"

    def _encrypt_des3(self, data: bytes) -> bytes:
        """Encrypt data with 3DES/ECB, padding with null bytes."""
        block_size = 8
        padding_len = block_size - len(data) % block_size
        data += b"\x00" * padding_len
        return self._cipher.encrypt(data)

    def _decrypt_des3(self, data: bytes) -> bytes:
        """Decrypt 3DES/ECB data, trimming to block boundary."""
        aligned = data[: len(data) - len(data) % 8]
        return self._cipher.decrypt(aligned)

    def _encrypt_aes(self, data: bytes) -> bytes:
        """Encrypt data with AES/CBC using the negotiated key and mixed IV.

        Uses the mixed IV from the last V4 message (even bytes from server IV,
        odd bytes from panel IV), matching the Java MsgWorker behavior.
        Falls back to server-only IV if no panel IV has been received yet.
        """
        if self._aes_key is None:
            _LOGGER.warning("AES encrypt called without AES key, falling back to 3DES")
            return self._encrypt_des3(data)
        block_size = 16
        padding_len = block_size - len(data) % block_size
        data += b"\x00" * padding_len
        iv = self._mixed_iv if self._mixed_iv is not None else self._server_iv
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
        return cipher.encrypt(data)

    @staticmethod
    def _scramble_key(key: bytes) -> bytes:
        """XOR the 3DES key with the OH protocol mask."""
        scrambled = bytearray(key)
        for i in range(len(_KEY_XOR_MASK)):
            scrambled[i] ^= _KEY_XOR_MASK[i]
        return bytes(scrambled)

    # Legacy compatibility aliases
    def get_scrambled_key(self) -> bytes:
        return self._scrambled_key

    def encrypt_data(self, data: bytes) -> bytes:
        return self._encrypt_des3(data)

    def decrypt_data(self, data: bytes) -> bytes:
        return self._decrypt_des3(data)

    def get_ack_response(self, ack: bool, encrypted: bool) -> bytes:
        return self._get_ack_response(ack, encrypted, is_v4=False)

    async def parse_event(self, peername: tuple, data: bytes) -> dict:
        return self._parse_v3_event(peername, data)


class OHServer:
    """Manages TCP server for Osborne Hoffman compatible devices.

    Opens a single port and listens for incoming TCP connections.
    Each connection gets its own encryption key and cipher.
    Supports V1-V3 (3DES) and V4 (AES/CBC with DH key exchange).
    """

    def __init__(
        self,
        host: str,
        port: int,
        accounts: dict[str, OHAccount],
        callback: Callable[[dict], Awaitable[bool]] | None = None,
        keystore: "OHKeyStore | None" = None,
    ) -> None:
        """Initialize instance."""
        self.host = host
        self.port = port
        self.accounts = accounts
        self.callback = callback
        self.keystore = keystore
        self.server: asyncio.Server | None = None

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Create a new OHConnection per incoming TCP connection."""
        conn = OHConnection(self)
        await conn(reader, writer)

    async def start_server(self, **kwargs) -> None:
        """Start the Osborne Hoffman TCP server."""
        _LOGGER.debug(
            "Starting Osborne Hoffman server on %s:%d.", self.host, self.port
        )
        self.server = await asyncio.start_server(
            self._handle_connection, host=self.host, port=self.port, **kwargs
        )

    async def close_server(self) -> None:
        """Stop the Osborne Hoffman server."""
        _LOGGER.debug("Stopping Osborne Hoffman server.")
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
