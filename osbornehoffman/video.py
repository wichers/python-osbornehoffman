"""Osborne Hoffman Video Verification server implementation.

Receives encrypted image/video clips from alarm panels with cameras.
Runs on a separate TCP port (default 9995) alongside the supervision server.

Supports V3 (AES/CTR with key exchange) and V4 (AES/CBC with pre-shared key).
"""

from __future__ import annotations

import asyncio
import logging
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from crc import Calculator, Crc16

from .server import (
    SIA_MATCHER,
    CID_MATCHER,
    V4_HEADER_MATCHER,
    MessageType,
)
from .tables import CID_SIA_MAPPING, SIA_EVENTS

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

# Response codes
VIDEO_READY = 0x14       # Ready signal / end-of-clip marker
VIDEO_ACK = 0x06         # Segment received OK
VIDEO_INVALID = 0x11     # Invalid header/format (17)
VIDEO_RETRY = 0x12       # Retry request (18, unencrypted only)
VIDEO_ERROR = 0x13       # Fatal error / CRC fail / restart (19)
VIDEO_NAK = 0x15         # General NAK (21)
VIDEO_KEY_ACK = 0x16     # V3 key exchange acknowledgment (22)

# Clip header offsets
CLIP_HEADER_ID = 0xFF
CLIP_FORMAT_VALID = 0x02
CLIP_FORMAT_END = 0xFF
CLIP_ENC_MARKER = 0xAA   # byte[12] == 0xAA → V3 encrypted
MAX_CLIP_SIZE = 524284

OFF_HEADER_ID = 12
OFF_HEADER_FORMAT = 13
OFF_CHECKSUM = 14
OFF_VIQ_STATUS = 15
OFF_TOTAL_BYTES = 16
OFF_CLIP_ID = 20
OFF_ZONE_NUMBER = 24
OFF_CAMERA_NUMBER = 26
OFF_CAMERA_PRE_RATE = 27
OFF_CAMERA_POST_RATE = 28
OFF_NUM_PRE_IMAGES = 29
OFF_NUM_POST_IMAGES = 30
OFF_TOTAL_IMAGES = 31
OFF_PRE_START_TIME = 32
OFF_POST_START_TIME = 36
OFF_POST_END_TIME = 40
OFF_ALARM_MSG_LEN = 44
OFF_ALARM_MSG = 45

V4_CLIP_HEADER_LEN = 48
V3_CLIP_HEADER_LEN = 45
V3_KEY_EXCHANGE_HEADER_LEN = 47

# SubHeader
SUB_HEADER_SIZE = 12

# V4 header (same as supervision)
V4_HEADER_LEN = 25
V4_IV_LEN = 16
V4_HEADER_IV_LEN = 41
V4_CRC_FIELD_LEN = 5

DEFAULT_VIDEO_PORT = 9995

_CRC_CALC = Calculator(Crc16.MODBUS)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ClipData:
    """Parsed clip header and image data."""

    header: bytearray = field(default_factory=lambda: bytearray(65536))
    header_bytes_read: int = 0
    image_data: bytearray = field(default_factory=lambda: bytearray(65536))
    image_bytes_read: int = 0
    crc_data: bytearray = field(default_factory=lambda: bytearray(345))
    crc_data_len: int = 0
    v4: bool = False

    def append_crc_data(self, data: bytes, offset: int = 0) -> None:
        """Append bytes to the CRC accumulator."""
        length = len(data) - offset
        self.crc_data[self.crc_data_len : self.crc_data_len + length] = data[offset:]
        self.crc_data_len += length

    @property
    def clip_data_size(self) -> int:
        return V4_CLIP_HEADER_LEN if self.v4 else V3_CLIP_HEADER_LEN

    # Field accessors
    @property
    def header_id(self) -> int:
        return self.header[OFF_HEADER_ID]

    @property
    def header_format(self) -> int:
        return self.header[OFF_HEADER_FORMAT]

    @property
    def viq_status(self) -> int:
        return self.header[OFF_VIQ_STATUS]

    @property
    def total_bytes_in_clip(self) -> int:
        return struct.unpack_from(">I", self.header, OFF_TOTAL_BYTES)[0]

    @property
    def clip_id(self) -> int:
        return struct.unpack_from(">I", self.header, OFF_CLIP_ID)[0]

    @property
    def zone_number(self) -> int:
        return struct.unpack_from(">H", self.header, OFF_ZONE_NUMBER)[0]

    @property
    def camera_number(self) -> int:
        return self.header[OFF_CAMERA_NUMBER]

    @property
    def camera_pre_rate(self) -> int:
        return self.header[OFF_CAMERA_PRE_RATE]

    @property
    def camera_post_rate(self) -> int:
        return self.header[OFF_CAMERA_POST_RATE]

    @property
    def num_pre_images(self) -> int:
        return self.header[OFF_NUM_PRE_IMAGES]

    @property
    def num_post_images(self) -> int:
        return self.header[OFF_NUM_POST_IMAGES]

    @property
    def total_images(self) -> int:
        return self.header[OFF_TOTAL_IMAGES]

    @property
    def pre_start_time(self) -> int:
        return struct.unpack_from(">I", self.header, OFF_PRE_START_TIME)[0]

    @property
    def post_start_time(self) -> int:
        return struct.unpack_from(">I", self.header, OFF_POST_START_TIME)[0]

    @property
    def post_end_time(self) -> int:
        return struct.unpack_from(">I", self.header, OFF_POST_END_TIME)[0]

    @property
    def alarm_message_length(self) -> int:
        return self.header[OFF_ALARM_MSG_LEN] & 0xFF

    @property
    def alarm_message(self) -> bytes:
        length = self.alarm_message_length
        return bytes(self.header[OFF_ALARM_MSG : OFF_ALARM_MSG + length])

    @property
    def file_extension(self) -> str:
        return ".jpg" if self.viq_status == 3 else ".asf"


@dataclass
class OHVideoEvent:
    """Represents a received video clip event."""

    peername: tuple
    clip_id: int
    camera_number: int
    zone_number: int
    viq_status: int
    file_extension: str
    total_images: int
    num_pre_images: int
    num_post_images: int
    camera_pre_rate: int
    camera_post_rate: int
    pre_start_time: int
    post_start_time: int
    post_end_time: int
    alarm_message: str
    image_data: bytes
    image_size: int
    is_v4: bool = False

    # Alarm event fields (parsed from embedded SIA/CID message)
    message_type: MessageType | None = None
    system_account: str | None = None
    account: str | None = None
    receiver: str | None = None
    line: str | None = None
    sequence: str | None = None
    sia_event: str | None = None
    sia_zone: str | None = None
    event_code: str | None = None
    zone: str | None = None
    area: str | None = None
    qualifier: str | None = None
    sia_type: str | None = None
    sia_description: str | None = None
    sia_concerns: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_padded_length(length: int) -> int:
    """Round up to AES block boundary."""
    if length % 16 != 0:
        return length + 16 - length % 16
    return length


def _gen_key_from_panel_id(panel_id_bytes: bytes) -> bytes:
    """Derive 16-byte AES key from 6-byte panel serial."""
    mask = 0
    for i in range(6):
        mask = (mask + (panel_id_bytes[i] & 0xFF)) & 0xFFFF
    key = bytearray([mask & 0xFF] * 16)
    for i in range(16):
        for j in range(16):
            key[j] = (key[j] ^ ((mask + j) << i)) & 0xFF
            key[i] = (key[i] ^ ((mask + i) >> j)) & 0xFF
    return bytes(key)


def _verify_xmit_checksum(
    header_12: bytes, payload: bytes, index: int, length: int
) -> int:
    """Verify XOR checksum over sub-header and payload.

    Returns xmit_counter on success, -1 on checksum failure.
    """
    # Zero-pad payload to 4-byte boundary
    padded = bytearray(length + 4)
    padded[:length] = payload[:length]

    checksum = 0
    xmit_counter = 0
    for i in range(0, 12, 4):
        word = int.from_bytes(header_12[i : i + 4], "big")
        checksum ^= word
        if i == 4:
            xmit_counter = word

    for i in range(index, length, 4):
        word = int.from_bytes(padded[i : i + 4], "big")
        checksum ^= word

    if checksum != 0:
        return -1
    return xmit_counter


def _verify_header_checksum(header: bytes, length: int) -> bool:
    """Verify XOR byte checksum of clip header."""
    checksum = 0
    for i in range(length):
        checksum ^= header[i]
    return checksum == 0


def _parse_alarm_message(data: str) -> dict | None:
    """Parse the embedded alarm message using SIA/CID matchers."""
    event: dict = {}

    if sia_match := SIA_MATCHER.match(data):
        event |= sia_match.groupdict()
        event["message_type"] = MessageType.SIA
    elif cid_match := CID_MATCHER.match(data):
        event |= cid_match.groupdict()
        event["message_type"] = MessageType.CID
        if (
            event.get("qualifier") is not None
            and event.get("event_code") is not None
        ):
            sub_map = CID_SIA_MAPPING.get(event["event_code"])
            if sub_map and sub_map.get(event["qualifier"]) is not None:
                event["sia_event"] = sub_map[event["qualifier"]]
    else:
        return None

    if event.get("sia_event") is not None and (
        sub_map := SIA_EVENTS.get(event["sia_event"])
    ):
        event["sia_type"] = sub_map.get("type")
        event["sia_description"] = sub_map.get("description")
        event["sia_concerns"] = sub_map.get("concerns")

    return event


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

class OHVideoConnection:
    """Handle a single video connection from a panel."""

    def __init__(self, server: OHVideoServer) -> None:
        self._server = server
        self._is_v4 = False
        self._is_encrypted = False
        self._iv: bytes | None = None
        self._aes_key: bytes | None = None
        self._ctr_cipher: AES = None  # V3 streaming cipher
        self._cbc_cipher_dec: AES = None  # V4 decryption cipher (recreated per op)
        self._cbc_cipher_enc: AES = None  # V4 encryption cipher (recreated per op)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def __call__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peername = writer.get_extra_info("peername")
        _LOGGER.debug("Video: new connection from %s", peername)
        self._reader = reader
        self._writer = writer

        try:
            clips_read = 0
            while True:
                clip = ClipData()
                self._reset_flags()

                if not await self._read_clip(clip, read_header=(clips_read == 0)):
                    break

                # Check image completeness
                if clip.image_bytes_read < clip.total_bytes_in_clip:
                    _LOGGER.debug(
                        "Video: incomplete image (%d < %d)",
                        clip.image_bytes_read,
                        clip.total_bytes_in_clip,
                    )
                    await self._send_byte(VIDEO_NAK)
                    continue

                # Build event and invoke callback
                await self._deliver_event(peername, clip)
                clips_read += 1
        except (ConnectionResetError, asyncio.IncompleteReadError):
            _LOGGER.debug("Video: connection reset from %s", peername)
        except Exception:
            _LOGGER.exception("Video: error processing connection from %s", peername)
        finally:
            _LOGGER.debug("Video: closing connection from %s", peername)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _reset_flags(self) -> None:
        """Reset per-clip flags."""
        if self._is_v4:
            self._is_encrypted = False

    # ------------------------------------------------------------------
    # Main clip read pipeline
    # ------------------------------------------------------------------

    async def _read_clip(self, clip: ClipData, read_header: bool) -> bool:
        """Read a complete clip. Returns True on success."""
        return (
            await self._read_v4_and_clip_header(
                read_header or self._is_v4, clip
            )
            and await self._read_alarm_message(clip)
            and await self._read_and_check_crc(clip)
            and self._validate_clip(clip)
            and await self._read_image(clip)
            and await self._check_ending_character()
        )

    # ------------------------------------------------------------------
    # Step 1: readV4AndClipHeader
    # ------------------------------------------------------------------

    async def _read_v4_and_clip_header(
        self, read_exchange_header: bool, clip: ClipData
    ) -> bool:
        bytes_read = 0
        header = clip.header

        # Send ready signal
        await self._send_byte(VIDEO_READY)
        _LOGGER.debug("Video: 0x14 sent, reading header")

        if read_exchange_header:
            bytes_read = await self._read_key_exchange_header(header, clip)
            if bytes_read < 0:
                return False

        # Read rest of the header
        bytes_read = await self._read_rest_of_header(bytes_read, header, clip)
        if bytes_read < 0:
            return False

        # V4: shift header by 3 bytes
        if self._is_v4:
            modified = bytearray(len(header))
            modified[: len(header) - 3] = header[3:]
            clip.header = modified
        # else: clip.header already points to header

        clip.header_bytes_read = bytes_read
        return True

    async def _read_key_exchange_header(
        self, header: bytearray, clip: ClipData
    ) -> int:
        """Read V4 or V3 key exchange header."""
        v4_or_v3_header = await self._read_v4_or_v3_header(clip)
        if v4_or_v3_header is None:
            return -1

        if self._is_v4:
            bytes_read = await self._read_v4_clip_header(v4_or_v3_header, header)
            if bytes_read < 0:
                return -1
            clip.append_crc_data(self._raw_clip_header)
            return bytes_read

        if self._is_encrypted:
            if not await self._negotiate_key_v3(v4_or_v3_header):
                _LOGGER.warning("Video: V3 key exchange failed")
                return -1
            return 0  # V3 encrypted: header was key exchange, not clip data

        # Unencrypted: header IS the clip header
        header[: len(v4_or_v3_header)] = v4_or_v3_header
        return len(v4_or_v3_header)

    async def _read_v4_or_v3_header(self, clip: ClipData) -> bytes | None:
        """Read first 25 bytes and detect V4 vs V3."""
        try:
            first_25 = await self._read_exact(V4_HEADER_LEN)
        except (IOError, asyncio.IncompleteReadError):
            _LOGGER.error("Video: failed reading initial header bytes")
            return None

        # Check for V4
        try:
            header_str = first_25.decode("ascii", errors="ignore")
        except Exception:
            header_str = ""

        if header_str.startswith("#40"):
            self._is_v4 = True
            self._is_encrypted = True
            clip.v4 = True

            # Read 16-byte IV
            try:
                self._iv = await self._read_exact(V4_IV_LEN)
            except (IOError, asyncio.IncompleteReadError):
                _LOGGER.error("Video: failed reading V4 IV")
                return None

            _LOGGER.debug("Video: V4 connection detected")

            # Append header + IV to CRC data
            v4_header_and_iv = bytearray(V4_HEADER_IV_LEN)
            v4_header_and_iv[:V4_HEADER_LEN] = first_25
            v4_header_and_iv[V4_HEADER_LEN:] = self._iv
            clip.append_crc_data(bytes(v4_header_and_iv))

            return first_25

        # V3: read remaining 22 bytes (total 47)
        try:
            rest = await self._read_exact(V3_KEY_EXCHANGE_HEADER_LEN - V4_HEADER_LEN)
        except (IOError, asyncio.IncompleteReadError):
            _LOGGER.error("Video: failed reading V3 header")
            return None

        v3_header = bytearray(V3_KEY_EXCHANGE_HEADER_LEN)
        v3_header[:V4_HEADER_LEN] = first_25
        v3_header[V4_HEADER_LEN:] = rest

        # Check encryption marker at byte 12
        if v3_header[OFF_HEADER_ID] == CLIP_ENC_MARKER:
            self._is_encrypted = True
            _LOGGER.debug("Video: V3 encrypted connection detected")
        else:
            _LOGGER.debug("Video: unencrypted connection detected")

        return bytes(v3_header)

    async def _read_v4_clip_header(
        self, v4_header: bytes, image_buffer: bytearray
    ) -> int:
        """Parse V4 header and decrypt clip header."""
        header_str = v4_header.decode("ascii", errors="ignore")
        v4_match = V4_HEADER_MATCHER.match(header_str)
        if not v4_match:
            _LOGGER.warning("Video: V4 header pattern match failed")
            return -1

        fields = v4_match.groupdict()
        recv_number = fields.get("receiver", "")
        line_number = fields.get("line", "")
        system_account = fields.get("system_account", "")

        # Read 48-byte encrypted clip header
        try:
            self._raw_clip_header = await self._read_exact(V4_CLIP_HEADER_LEN)
        except (IOError, asyncio.IncompleteReadError):
            _LOGGER.warning("Video: failed reading V4 clip header")
            return -1

        # Look up AES key by account
        aes_key = self._find_aes_key(system_account)
        if aes_key is None:
            _LOGGER.warning(
                "Video: no AES key for account %s", system_account
            )
            return -1

        # Decrypt clip header using the class-level CBC cipher so that
        # CBC state carries forward to subsequent reads (alarm, segments).
        # The test client / Java server use a continuous cipher — no re-init.
        try:
            self._cbc_cipher_dec = AES.new(aes_key, AES.MODE_CBC, self._iv)
            decrypted = self._cbc_cipher_dec.decrypt(self._raw_clip_header)
        except Exception as exc:
            _LOGGER.warning("Video: AES decryption failed: %s", exc)
            return -1

        _LOGGER.debug("Video: V4 decrypted clip header: %s", decrypted[:48].hex())

        # Validate format: bytes[0:3] == 0x00 and byte[16] == 0x02
        if not (
            decrypted[0] == 0
            and decrypted[1] == 0
            and decrypted[2] == 0
            and decrypted[16] == CLIP_FORMAT_VALID
        ):
            _LOGGER.warning("Video: V4 clip header format invalid")
            return -1

        # Store decrypted header and AES key for subsequent decryption
        image_buffer[:V4_CLIP_HEADER_LEN] = decrypted[:V4_CLIP_HEADER_LEN]
        self._aes_key = aes_key

        # Enc cipher is separate (used for server ACKs)
        self._cbc_cipher_enc = AES.new(aes_key, AES.MODE_CBC, self._iv)

        return V4_CLIP_HEADER_LEN

    async def _negotiate_key_v3(self, header: bytes) -> bool:
        """V3 key exchange.

        47-byte header contains R/L numbers, panel serial, and
        32 encrypted bytes with AES key material.
        """
        # Extract R-number, L-number, panel serial
        r_number = header[0:4]
        l_number = header[4:8]
        panel_sn = bytearray(6)
        panel_sn[0:4] = header[8:12]
        panel_sn[4:6] = header[13:15]

        rla = (
            "R" + r_number.decode("ascii", errors="ignore")
            + "L" + l_number.decode("ascii", errors="ignore")
            + "    " + panel_sn.decode("ascii", errors="ignore").upper()
        )
        _LOGGER.debug("Video V3: panel RLA = %s", rla)

        # Look up panel ID from accounts
        panel_id_bytes = self._find_panel_id(panel_sn)
        if panel_id_bytes is None:
            _LOGGER.error("Video V3: panel not found for RLA %s", rla)
            return False

        # Derive temp key from panel ID
        temp_key = _gen_key_from_panel_id(panel_id_bytes)

        # Decrypt header[15:47] (32 bytes) with AES/ECB
        try:
            cipher = AES.new(temp_key, AES.MODE_ECB)
            decrypted = cipher.decrypt(header[15:47])
        except Exception as exc:
            _LOGGER.error("Video V3: decryption failed: %s", exc)
            return False

        # Parse decrypted data
        encryption_key = bytearray(16)
        encryption_key[0:8] = decrypted[0:8]
        init_vector = decrypted[8:24]
        received_crc = decrypted[24:26]

        # Validate CRC (bytes are swapped in comparison!)
        computed_crc = _CRC_CALC.checksum(decrypted[0:24])
        computed_high = (computed_crc >> 8) & 0xFF
        computed_low = computed_crc & 0xFF
        if received_crc[0] != computed_low or received_crc[1] != computed_high:
            _LOGGER.error("Video V3: CRC mismatch")
            await self._send_byte(VIDEO_ERROR)
            return False

        _LOGGER.debug("Video V3: CRC correct")

        # Generate server's half of the key (8 bytes)
        server_key_half = get_random_bytes(16)[:8]
        encryption_key[8:16] = server_key_half

        # Build response: [server_key_half(8)] + [CRC(2)] + [padding(6)]
        response = bytearray(16)
        response[0:8] = server_key_half
        server_crc = _CRC_CALC.checksum(server_key_half)
        response[8] = (server_crc >> 8) & 0xFF
        response[9] = server_crc & 0xFF
        # response[10:16] stays zero

        # Encrypt response with AES/ECB using temp key
        cipher = AES.new(temp_key, AES.MODE_ECB)
        encrypted_response = cipher.encrypt(bytes(response))

        # Send: 0x16 + encrypted response (17 bytes)
        msg = bytes([VIDEO_KEY_ACK]) + encrypted_response
        self._writer.write(msg)
        await self._writer.drain()

        # Initialize AES/CTR cipher for subsequent data
        self._aes_key = bytes(encryption_key)
        self._iv = bytes(init_vector)
        self._ctr_cipher = AES.new(
            self._aes_key, AES.MODE_CTR, nonce=b"", initial_value=self._iv
        )
        self._is_encrypted = True

        _LOGGER.debug("Video V3: key exchange complete")
        return True

    async def _read_rest_of_header(
        self, bytes_read: int, header: bytearray, clip: ClipData
    ) -> int:
        """Read remaining clip header bytes."""
        header_length = clip.clip_data_size
        if bytes_read >= header_length:
            return bytes_read

        remaining = header_length - bytes_read
        try:
            if self._is_v4:
                padded_len = _get_padded_length(remaining)
                raw = await self._read_exact(padded_len)
                decrypted = self._decrypt(raw)
                header[bytes_read : bytes_read + remaining] = decrypted[:remaining]
                clip.append_crc_data(raw)
            elif self._is_encrypted:
                raw = await self._read_exact(remaining)
                decrypted = self._decrypt(raw)
                header[bytes_read : bytes_read + remaining] = decrypted[:remaining]
            else:
                raw = await self._read_exact(remaining)
                header[bytes_read : bytes_read + remaining] = raw
                clip.append_crc_data(raw)

            bytes_read += remaining
        except (IOError, asyncio.IncompleteReadError):
            _LOGGER.error("Video: failed reading rest of header")
            return -1

        return bytes_read

    # ------------------------------------------------------------------
    # Step 2: readAlarmMessage
    # ------------------------------------------------------------------

    async def _read_alarm_message(self, clip: ClipData) -> bool:
        """Read the alarm message from the clip header."""
        alarm_length = clip.alarm_message_length
        _LOGGER.debug("Video: reading alarm message (%d bytes)", alarm_length)

        if alarm_length == 0:
            return True

        try:
            if self._is_v4:
                padded_len = _get_padded_length(alarm_length)
                raw = await self._read_exact(padded_len)
                decrypted = self._decrypt(raw)
                clip.header[OFF_ALARM_MSG : OFF_ALARM_MSG + alarm_length] = (
                    decrypted[:alarm_length]
                )
                clip.append_crc_data(raw)
            elif self._is_encrypted:
                raw = await self._read_exact(alarm_length)
                decrypted = self._decrypt(raw)
                clip.header[OFF_ALARM_MSG : OFF_ALARM_MSG + alarm_length] = (
                    decrypted[:alarm_length]
                )
            else:
                raw = await self._read_exact(alarm_length)
                clip.header[OFF_ALARM_MSG : OFF_ALARM_MSG + alarm_length] = raw

            clip.header_bytes_read = clip.clip_data_size + alarm_length
        except (IOError, asyncio.IncompleteReadError):
            _LOGGER.error("Video: failed reading alarm message")
            await self._send_byte(VIDEO_ERROR)
            return False

        _LOGGER.debug(
            "Video: alarm message: %s", clip.alarm_message.decode("ascii", errors="ignore")
        )
        return True

    # ------------------------------------------------------------------
    # Step 3: readAndCheckCRC (V4 only)
    # ------------------------------------------------------------------

    async def _read_and_check_crc(self, clip: ClipData) -> bool:
        """Validate CRC for V4 messages."""
        if not self._is_v4:
            return True

        try:
            crc_field = await self._read_exact(V4_CRC_FIELD_LEN)
        except (IOError, asyncio.IncompleteReadError):
            _LOGGER.error("Video: failed reading CRC field")
            return False

        if crc_field[0:1] != b"C":
            _LOGGER.warning(
                "Video: expected 'C' prefix in CRC, got %r", crc_field[0:1]
            )
            return False

        try:
            received_crc = crc_field[1:5].decode("ascii")
        except UnicodeDecodeError:
            _LOGGER.warning("Video: invalid CRC field encoding")
            return False

        computed = _CRC_CALC.checksum(
            bytes(clip.crc_data[: clip.crc_data_len])
        )
        computed_hex = f"{computed:04X}"

        if computed_hex.upper() != received_crc.upper():
            _LOGGER.warning(
                "Video V4: CRC mismatch (computed=%s, received=%s)",
                computed_hex,
                received_crc,
            )
            return False

        _LOGGER.debug("Video V4: CRC OK")
        clip.header_bytes_read += V4_CRC_FIELD_LEN
        return True

    # ------------------------------------------------------------------
    # Step 4: validateClip
    # ------------------------------------------------------------------

    def _validate_clip(self, clip: ClipData) -> bool:
        """Validate clip header. Synchronous."""
        header = clip.header
        alarm_length = clip.alarm_message_length
        clip_header_size = V3_CLIP_HEADER_LEN + alarm_length

        if clip.header_bytes_read < clip_header_size:
            _LOGGER.debug(
                "Video: header too short (%d < %d)",
                clip.header_bytes_read,
                clip_header_size,
            )
            asyncio.ensure_future(self._send_byte(VIDEO_INVALID))
            return False

        if header[OFF_HEADER_ID] != CLIP_HEADER_ID:
            _LOGGER.debug("Video: invalid clip ID %02X", header[OFF_HEADER_ID])
            asyncio.ensure_future(self._send_byte(VIDEO_INVALID))
            return False

        # Verify XmitCheckSum over sub-header + rest of header
        xmit_counter = _verify_xmit_checksum(
            bytes(header[:SUB_HEADER_SIZE]),
            bytes(header),
            SUB_HEADER_SIZE,
            clip_header_size,
        )
        if xmit_counter != 0:
            _LOGGER.debug("Video: invalid transmit checksum")
            asyncio.ensure_future(self._send_byte(VIDEO_INVALID))
            return False

        # Verify byte XOR checksum
        if not _verify_header_checksum(bytes(header), clip_header_size):
            _LOGGER.debug("Video: invalid header checksum")
            asyncio.ensure_future(self._send_byte(VIDEO_INVALID))
            return False

        # End clip marker
        if header[OFF_HEADER_FORMAT] == CLIP_FORMAT_END:
            _LOGGER.debug("Video: end clip received")
            asyncio.ensure_future(self._send_byte(VIDEO_ACK))
            return False

        if header[OFF_HEADER_FORMAT] != CLIP_FORMAT_VALID:
            _LOGGER.debug(
                "Video: invalid clip format %02X", header[OFF_HEADER_FORMAT]
            )
            asyncio.ensure_future(self._send_byte(VIDEO_INVALID))
            return False

        total_bytes = clip.total_bytes_in_clip
        if total_bytes > MAX_CLIP_SIZE:
            _LOGGER.debug("Video: clip too large (%d bytes)", total_bytes)
            asyncio.ensure_future(self._send_byte(VIDEO_ERROR))
            return False

        _LOGGER.debug(
            "Video: clip ID=%d, images=%d (pre=%d, post=%d), "
            "camera=%d, zone=%d, size=%d bytes",
            clip.clip_id,
            clip.total_images,
            clip.num_pre_images,
            clip.num_post_images,
            clip.camera_number,
            clip.zone_number,
            total_bytes,
        )
        return True

    # ------------------------------------------------------------------
    # Step 5: readImage
    # ------------------------------------------------------------------

    async def _read_image(self, clip: ClipData) -> bool:
        """Read image data segments."""
        total_bytes = clip.total_bytes_in_clip
        read_length = 0
        expected_counter = 1

        _LOGGER.debug("Video: ACKing header, reading %d bytes of image data", total_bytes)
        await self._send_byte(VIDEO_ACK)

        while read_length < total_bytes:
            try:
                # Read 12-byte SubHeader
                if self._is_v4:
                    sub_raw = await self._read_exact(
                        _get_padded_length(SUB_HEADER_SIZE)
                    )
                    sub_dec = self._decrypt(sub_raw)
                    # TrimLeft: take last 12 bytes
                    trim = _get_padded_length(SUB_HEADER_SIZE) - SUB_HEADER_SIZE
                    sub_header = sub_dec[trim : trim + SUB_HEADER_SIZE]
                elif self._is_encrypted:
                    sub_raw = await self._read_exact(SUB_HEADER_SIZE)
                    sub_header = self._decrypt(sub_raw)
                else:
                    sub_header = await self._read_exact(SUB_HEADER_SIZE)

                xmit_length = int.from_bytes(sub_header[0:4], "big")
                payload_length = xmit_length - SUB_HEADER_SIZE

                # Read payload
                if self._is_v4:
                    padded = _get_padded_length(payload_length)
                    raw_payload = await self._read_exact(padded)
                    decrypted_payload = self._decrypt(raw_payload)
                    payload = decrypted_payload[:payload_length]
                elif self._is_encrypted:
                    raw_payload = await self._read_exact(payload_length)
                    payload = self._decrypt(raw_payload)
                else:
                    payload = await self._read_exact(payload_length)

                # Store image data
                clip.image_data[read_length : read_length + payload_length] = (
                    payload[:payload_length]
                )

                # Verify XOR checksum
                xmit_counter = _verify_xmit_checksum(
                    sub_header,
                    payload,
                    0,
                    payload_length,
                )

                if xmit_counter == -1:
                    _LOGGER.debug("Video: invalid transmit checksum in data")
                    if not self._is_encrypted:
                        await self._send_byte(VIDEO_RETRY)
                    continue

                if xmit_counter == 0:
                    _LOGGER.debug("Video: header counter received in data")
                    if not self._is_encrypted:
                        await self._send_byte(VIDEO_ERROR)
                        return False
                    continue

                if xmit_counter != expected_counter:
                    _LOGGER.debug(
                        "Video: counter mismatch (got %d, expected %d)",
                        xmit_counter,
                        expected_counter,
                    )
                    if not self._is_encrypted:
                        await self._send_byte(VIDEO_ERROR)
                        return False
                    continue

                await self._send_byte(VIDEO_ACK)
                expected_counter += 1
                read_length += payload_length

            except (IOError, asyncio.IncompleteReadError):
                _LOGGER.error("Video: IO error reading image data")
                await self._send_byte(VIDEO_ERROR)
                return False

        clip.image_bytes_read = read_length
        return True

    # ------------------------------------------------------------------
    # Step 6: checkEndingCharacter
    # ------------------------------------------------------------------

    async def _check_ending_character(self) -> bool:
        """Verify end-of-clip marker."""
        try:
            if self._is_v4 and self._is_encrypted:
                raw = await self._read_exact(_get_padded_length(1))
                data = self._decrypt(raw)
            elif self._is_encrypted:
                raw = await self._read_exact(1)
                data = self._decrypt(raw)
            else:
                data = await self._read_exact(1)

            if data[0] != VIDEO_READY:
                _LOGGER.debug(
                    "Video: expected ending 0x14, got 0x%02X", data[0]
                )
                await self._send_byte(VIDEO_ERROR)
                return False
        except (IOError, asyncio.IncompleteReadError):
            _LOGGER.error("Video: IO error reading ending character")
            return False

        return True

    # ------------------------------------------------------------------
    # Event delivery
    # ------------------------------------------------------------------

    async def _deliver_event(self, peername: tuple, clip: ClipData) -> None:
        """Parse alarm message and invoke the user callback."""
        alarm_str = clip.alarm_message.decode("ascii", errors="ignore")
        _LOGGER.debug("Video: alarm data: %s", alarm_str)

        # Parse the embedded SIA/CID alarm message
        parsed = _parse_alarm_message(alarm_str)

        event = OHVideoEvent(
            peername=peername,
            clip_id=clip.clip_id,
            camera_number=clip.camera_number,
            zone_number=clip.zone_number,
            viq_status=clip.viq_status,
            file_extension=clip.file_extension,
            total_images=clip.total_images,
            num_pre_images=clip.num_pre_images,
            num_post_images=clip.num_post_images,
            camera_pre_rate=clip.camera_pre_rate,
            camera_post_rate=clip.camera_post_rate,
            pre_start_time=clip.pre_start_time,
            post_start_time=clip.post_start_time,
            post_end_time=clip.post_end_time,
            alarm_message=alarm_str,
            image_data=bytes(clip.image_data[: clip.image_bytes_read]),
            image_size=clip.image_bytes_read,
            is_v4=self._is_v4,
        )

        if parsed:
            event.message_type = parsed.get("message_type")
            event.system_account = parsed.get("system_account")
            event.account = parsed.get("account")
            event.receiver = parsed.get("receiver")
            event.line = parsed.get("line")
            event.sequence = parsed.get("sequence")
            event.sia_event = parsed.get("sia_event")
            event.sia_zone = parsed.get("sia_zone")
            event.event_code = parsed.get("event_code")
            event.zone = parsed.get("zone")
            event.area = parsed.get("area")
            event.qualifier = parsed.get("qualifier")
            event.sia_type = parsed.get("sia_type")
            event.sia_description = parsed.get("sia_description")
            event.sia_concerns = parsed.get("sia_concerns")

        if self._server.callback is not None:
            try:
                await self._server.callback(event)
            except Exception:
                _LOGGER.exception("Video: error in event callback")

    # ------------------------------------------------------------------
    # I/O and encryption helpers
    # ------------------------------------------------------------------

    async def _read_exact(self, n: int) -> bytes:
        """Read exactly n bytes from the stream."""
        data = b""
        while len(data) < n:
            chunk = await self._reader.read(n - len(data))
            if not chunk:
                raise IOError("End of stream")
            data += chunk
        return data

    async def _send_byte(self, byte_val: int) -> None:
        """Send single-byte response, encrypted if V4."""
        if self._is_v4 and self._is_encrypted:
            data = bytearray(16)
            data[0] = byte_val
            data = self._encrypt(bytes(data))
        else:
            data = bytes([byte_val])
        self._writer.write(data)
        await self._writer.drain()

    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt data using the active cipher."""
        if self._is_v4 and self._cbc_cipher_dec is not None:
            return self._cbc_cipher_dec.decrypt(data)
        if self._ctr_cipher is not None:
            return self._ctr_cipher.decrypt(data)
        return data  # unencrypted

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data using the active cipher."""
        if self._is_v4 and self._cbc_cipher_enc is not None:
            return self._cbc_cipher_enc.encrypt(data)
        if self._ctr_cipher is not None:
            return self._ctr_cipher.encrypt(data)
        return data

    def _find_aes_key(self, system_account: str) -> bytes | None:
        """Look up AES key for an account."""
        if self._server.keystore is not None:
            return self._server.keystore.get_aes_key(system_account)
        return None

    def _find_panel_id(self, panel_sn: bytes) -> bytes | None:
        """Look up panel ID bytes from the account config.

        For V3 video key exchange, the panel sends its serial number.
        We try to match it against registered accounts.
        """
        account_str = panel_sn.decode("ascii", errors="ignore").upper()
        acct = self._server.accounts.get(account_str)
        if acct is not None and acct.panel_id:
            # Convert panel_id int to 6-byte representation
            hex_str = f"{acct.panel_id:012X}"
            return bytes.fromhex(hex_str)[-6:]
        # Fallback: use the panel_sn bytes directly
        return panel_sn


# ---------------------------------------------------------------------------
# Video TCP Server
# ---------------------------------------------------------------------------

class OHVideoServer:
    """TCP server for OH Video Verification."""

    def __init__(
        self,
        host: str,
        port: int,
        accounts: dict[str, "OHAccount"],
        callback: Callable[[OHVideoEvent], Awaitable[None]] | None = None,
        keystore: "OHKeyStore | None" = None,
    ) -> None:
        self.host = host
        self.port = port
        self.accounts = accounts
        self.callback = callback
        self.keystore = keystore
        self.server: asyncio.Server | None = None

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn = OHVideoConnection(self)
        await conn(reader, writer)

    async def start(self) -> None:
        """Start the video TCP server."""
        _LOGGER.debug(
            "Starting OH Video server on %s:%d", self.host, self.port
        )
        self.server = await asyncio.start_server(
            self._handle_connection, host=self.host, port=self.port
        )

    async def stop(self) -> None:
        """Stop the video TCP server."""
        _LOGGER.debug("Stopping OH Video server")
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
