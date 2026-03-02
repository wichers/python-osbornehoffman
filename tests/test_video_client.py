#!/usr/bin/python
"""OH Video test client — simulates a panel sending video clips.

Tests V3 (unencrypted/encrypted) and V4 protocol paths against
an OH receiver (Java NetRec or local Python OHServer).

Usage:
    python tests/test_video_client.py --protocol v3
    python tests/test_video_client.py --protocol v3-enc --panel-serial 001234
    python tests/test_video_client.py --protocol v4 --aes-key <hex>
    python tests/test_video_client.py --protocol v4  # does DH on supervision port first
    python tests/test_video_client.py --protocol all
"""

import argparse
import asyncio
import json
import logging
import struct
import sys
import time
from pathlib import Path

from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.asn1 import DerSequence
from crc import Calculator, Crc16

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)-8s %(message)s")
_LOGGER = logging.getLogger(__name__)

# ==================== Protocol Constants ====================

VIDEO_READY = 0x14
VIDEO_ACK = 0x06
VIDEO_INVALID = 0x11
VIDEO_RETRY = 0x12
VIDEO_ERROR = 0x13
VIDEO_NAK = 0x15
VIDEO_KEY_ACK = 0x16

CLIP_HEADER_ID = 0xFF
CLIP_FORMAT_VALID = 0x02
CLIP_ENC_MARKER = 0xAA

V4_HEADER_LEN = 25
V4_IV_LEN = 16
V4_CLIP_HEADER_LEN = 48
V3_CLIP_HEADER_LEN = 45
V3_KEY_EXCHANGE_HEADER_LEN = 47
SUB_HEADER_SIZE = 12
V4_CRC_FIELD_LEN = 5

DEFAULT_SEGMENT_SIZE = 1024

_CRC_CALC = Calculator(Crc16.MODBUS)

# 3DES key XOR mask (from OH protocol spec)
_KEY_XOR_MASK = bytes([
    0x55, 0x2D, 0x6A, 0x05, 0x23, 0x49, 0x39, 0xA8,
    0x45, 0x29, 0xD3, 0xE9, 0x94, 0xC2, 0xB5, 0x88,
    0x45, 0xA3, 0x50, 0x8A, 0x44, 0xAA, 0x69, 0x54,
])

RESPONSE_NAMES = {
    VIDEO_READY: "READY(0x14)",
    VIDEO_ACK: "ACK(0x06)",
    VIDEO_INVALID: "INVALID(0x11)",
    VIDEO_RETRY: "RETRY(0x12)",
    VIDEO_ERROR: "ERROR(0x13)",
    VIDEO_NAK: "NAK(0x15)",
    VIDEO_KEY_ACK: "KEY_ACK(0x16)",
}


# ==================== Helpers ====================

def _get_padded_length(length: int) -> int:
    """Round up to AES block boundary (16 bytes)."""
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


# ==================== Checksum Builders ====================

def build_checksums(header: bytearray, total_length: int) -> None:
    """Set header[8:12] (XmitCheckSum) and header[14] (byte XOR checksum).

    Both must be simultaneously valid:
    - XOR of all 4-byte big-endian words = 0
    - XOR of all individual bytes = 0
    Iterates until both converge (typically 2-3 rounds).
    """
    header[8:12] = b"\x00\x00\x00\x00"
    header[14] = 0

    for _ in range(5):
        # Compute XmitCheckSum (word XOR)
        header[8:12] = b"\x00\x00\x00\x00"
        padded = bytearray(total_length + 4)
        padded[:total_length] = header[:total_length]
        word_xor = 0
        for i in range(0, 12, 4):
            word_xor ^= int.from_bytes(header[i : i + 4], "big")
        for i in range(12, total_length, 4):
            word_xor ^= int.from_bytes(padded[i : i + 4], "big")
        struct.pack_into(">I", header, 8, word_xor)

        # Compute byte XOR checksum
        byte_xor = 0
        for i in range(total_length):
            byte_xor ^= header[i]
        if byte_xor == 0:
            break
        header[14] ^= byte_xor


def build_sub_header(payload: bytes, counter: int) -> bytes:
    """Build a 12-byte SubHeader for an image segment."""
    xmit_length = SUB_HEADER_SIZE + len(payload)
    sub = bytearray(SUB_HEADER_SIZE)
    struct.pack_into(">I", sub, 0, xmit_length)
    struct.pack_into(">I", sub, 4, counter)
    # Compute XmitCheckSum: XOR of all words in sub + payload = 0
    padded = bytearray(len(payload) + 4)
    padded[: len(payload)] = payload
    word_xor = int.from_bytes(sub[0:4], "big") ^ int.from_bytes(sub[4:8], "big")
    for i in range(0, len(padded), 4):
        word_xor ^= int.from_bytes(padded[i : i + 4], "big")
    struct.pack_into(">I", sub, 8, word_xor)
    return bytes(sub)


# ==================== Clip Header Builder ====================

def build_clip_header(
    alarm_msg: bytes,
    image_data_size: int,
    clip_id: int = 1,
    zone: int = 1,
    camera: int = 1,
    viq_status: int = 3,
) -> bytearray:
    """Build a 45-byte V3 clip header + alarm message appended.

    Returns a bytearray of size 45 + len(alarm_msg) with valid checksums.
    """
    total_length = V3_CLIP_HEADER_LEN + len(alarm_msg)
    header = bytearray(total_length)

    # XmitLength covers full header + alarm
    struct.pack_into(">I", header, 0, total_length)
    # XmitCounter = 0 for clip header
    struct.pack_into(">I", header, 4, 0)
    # XmitCheckSum placeholder
    struct.pack_into(">I", header, 8, 0)
    # HeaderID
    header[12] = CLIP_HEADER_ID
    # HeaderFormat
    header[13] = CLIP_FORMAT_VALID
    # Checksum placeholder
    header[14] = 0
    # ViqStatus
    header[15] = viq_status
    # TotalBytesInClip
    struct.pack_into(">I", header, 16, image_data_size)
    # ClipID
    struct.pack_into(">I", header, 20, clip_id)
    # ZoneNumber
    struct.pack_into(">H", header, 24, zone)
    # CameraNumber
    header[26] = camera
    # Rates
    header[27] = 5   # pre rate
    header[28] = 5   # post rate
    # Image counts
    header[29] = 1   # pre images
    header[30] = 1   # post images
    header[31] = 2   # total images
    # Timestamps
    now = int(time.time())
    struct.pack_into(">I", header, 32, now - 5)   # pre start
    struct.pack_into(">I", header, 36, now)        # post start
    struct.pack_into(">I", header, 40, now + 5)    # post end
    # Alarm message length
    header[44] = len(alarm_msg)
    # Alarm message data
    header[45 : 45 + len(alarm_msg)] = alarm_msg

    # Compute both checksums
    build_checksums(header, total_length)
    return header


def build_alarm_message(receiver: int, line: int, account: int) -> bytes:
    """Build a SIA burglary alarm message."""
    msg = (
        f'\n01010034"SIA-DCS"0001R{receiver:04X}L{line:04X}'
        f"[#{account:06X}|Nri01/BA001]\r\x00"
    )
    return msg.encode("ascii")


# ==================== V3 Unencrypted ====================

async def test_v3_unencrypted(args) -> tuple[bool, str]:
    """Send a video clip using V3 unencrypted protocol."""
    reader, writer = await asyncio.open_connection(args.host, args.video_port)
    try:
        # Step 1: Receive READY
        ready = await asyncio.wait_for(reader.readexactly(1), timeout=10)
        _LOGGER.info("V3: received %s", RESPONSE_NAMES.get(ready[0], f"0x{ready[0]:02X}"))
        if ready[0] != VIDEO_READY:
            return False, f"Expected READY(0x14), got 0x{ready[0]:02X}"

        # Build clip data
        alarm_msg = build_alarm_message(args.receiver, args.line, args.account)
        image_data = _get_image_data(args)
        viq = 3 if getattr(args, "format", "jpeg") == "jpeg" else 1
        clip_header = build_clip_header(
            alarm_msg, len(image_data),
            clip_id=args.clip_id, zone=args.zone, camera=args.camera,
            viq_status=viq,
        )

        # Step 2: Send 47-byte header (45 clip header + first 2 alarm bytes)
        # The server reads 47 bytes into the header buffer, so positions [45:47]
        # must contain the first 2 bytes of the alarm message (not zero padding).
        writer.write(bytes(clip_header[:V3_KEY_EXCHANGE_HEADER_LEN]))
        await writer.drain()
        _LOGGER.info("V3: sent 47-byte header (includes alarm[0:2])")

        # Step 3: Send remaining alarm bytes (alarm[2:])
        remaining_alarm = bytes(clip_header[V3_KEY_EXCHANGE_HEADER_LEN:])
        writer.write(remaining_alarm)
        await writer.drain()
        _LOGGER.info("V3: sent remaining alarm (%d bytes)", len(remaining_alarm))

        # Step 4: Receive ACK after validation
        ack = await asyncio.wait_for(reader.readexactly(1), timeout=10)
        _LOGGER.info("V3: received %s", RESPONSE_NAMES.get(ack[0], f"0x{ack[0]:02X}"))
        if ack[0] != VIDEO_ACK:
            return False, f"Clip header rejected: {RESPONSE_NAMES.get(ack[0], f'0x{ack[0]:02X}')}"

        # Step 5: Send image data segments
        ok, detail = await _send_image_segments(reader, writer, image_data, args.segment_size)
        if not ok:
            return False, detail

        # Step 6: Send end marker
        writer.write(bytes([VIDEO_READY]))
        await writer.drain()
        _LOGGER.info("V3: sent end marker (0x14)")

        return True, "V3 unencrypted clip sent successfully"

    except asyncio.TimeoutError:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)
    finally:
        writer.close()
        await writer.wait_closed()


async def _send_image_segments(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    image_data: bytes,
    segment_size: int,
    encrypt_fn=None,
    decrypt_fn=None,
    is_v4: bool = False,
) -> tuple[bool, str]:
    """Send image data as sub-header + payload segments."""
    counter = 1
    offset = 0
    while offset < len(image_data):
        chunk = image_data[offset : offset + segment_size]
        sub_header = build_sub_header(chunk, counter)

        if is_v4 and encrypt_fn:
            # TrimLeft: place 12-byte sub-header at offset 4 in 16-byte block
            sub_block = bytearray(16)
            sub_block[4:16] = sub_header
            encrypted_sub = encrypt_fn(bytes(sub_block))
            # Pad payload to 16-byte boundary
            padded_len = _get_padded_length(len(chunk))
            padded_chunk = bytearray(padded_len)
            padded_chunk[: len(chunk)] = chunk
            encrypted_payload = encrypt_fn(bytes(padded_chunk))
            writer.write(encrypted_sub + encrypted_payload)
        elif encrypt_fn:
            # V3 encrypted: encrypt sub-header + payload directly
            writer.write(encrypt_fn(sub_header + chunk))
        else:
            writer.write(sub_header + chunk)

        await writer.drain()

        # Receive ACK
        if is_v4 and decrypt_fn:
            ack_raw = await asyncio.wait_for(reader.readexactly(16), timeout=10)
            ack_data = decrypt_fn(ack_raw)
            ack_byte = ack_data[0]
        else:
            ack_raw = await asyncio.wait_for(reader.readexactly(1), timeout=10)
            ack_byte = ack_raw[0]

        if ack_byte != VIDEO_ACK:
            return False, f"Segment {counter} rejected: {RESPONSE_NAMES.get(ack_byte, f'0x{ack_byte:02X}')}"
        _LOGGER.debug("  segment %d ACK (%d bytes)", counter, len(chunk))

        counter += 1
        offset += len(chunk)

    return True, f"{counter - 1} segments sent"


# ==================== V3 Encrypted ====================

async def test_v3_encrypted(args) -> tuple[bool, str]:
    """Send a video clip using V3 encrypted protocol (AES/CTR with key exchange)."""
    reader, writer = await asyncio.open_connection(args.host, args.video_port)
    try:
        # Step 1: Receive READY
        ready = await asyncio.wait_for(reader.readexactly(1), timeout=10)
        _LOGGER.info("V3-enc: received %s", RESPONSE_NAMES.get(ready[0], f"0x{ready[0]:02X}"))
        if ready[0] != VIDEO_READY:
            return False, f"Expected READY(0x14), got 0x{ready[0]:02X}"

        # Step 2: Build and send key exchange header
        panel_serial = args.panel_serial.encode("ascii")[:6].ljust(6, b"0")
        # Derive temp key from panel_id (same as server: panel_id int → 6 bytes)
        panel_id_hex = f"{args.panel_id:012X}"
        panel_id_bytes = bytes.fromhex(panel_id_hex)[-6:]
        temp_key = _gen_key_from_panel_id(panel_id_bytes)

        # Generate panel's key half and IV
        panel_key_half = get_random_bytes(8)
        iv = get_random_bytes(16)

        # Build key material (32 bytes)
        key_material = bytearray(32)
        key_material[0:8] = panel_key_half
        key_material[8:24] = iv
        # CRC of first 24 bytes, bytes swapped (low byte first, high byte second)
        crc = _CRC_CALC.checksum(bytes(key_material[:24]))
        key_material[24] = crc & 0xFF          # low byte
        key_material[25] = (crc >> 8) & 0xFF    # high byte
        # bytes 26-31 = zeros (padding)

        # Encrypt key material with AES/ECB using temp key
        ecb_cipher = AES.new(temp_key, AES.MODE_ECB)
        encrypted_key_material = ecb_cipher.encrypt(bytes(key_material))

        # Build 47-byte header
        r_num = f"{args.receiver:04X}".encode("ascii")
        l_num = f"{args.line:04X}".encode("ascii")
        kex_header = bytearray(V3_KEY_EXCHANGE_HEADER_LEN)
        kex_header[0:4] = r_num
        kex_header[4:8] = l_num
        kex_header[8:12] = panel_serial[0:4]
        kex_header[12] = CLIP_ENC_MARKER  # 0xAA
        kex_header[13:15] = panel_serial[4:6]
        kex_header[15:47] = encrypted_key_material

        writer.write(bytes(kex_header))
        await writer.drain()
        _LOGGER.info("V3-enc: sent 47-byte key exchange header")

        # Step 3: Receive key exchange response (17 bytes)
        kex_response = await asyncio.wait_for(reader.readexactly(17), timeout=10)
        if kex_response[0] != VIDEO_KEY_ACK:
            return False, f"Key exchange rejected: 0x{kex_response[0]:02X}"

        # Decrypt server's response
        server_encrypted = kex_response[1:17]
        server_decrypted = ecb_cipher.decrypt(server_encrypted)
        server_key_half = server_decrypted[0:8]

        _LOGGER.info("V3-enc: key exchange accepted, server key half received")

        # Step 4: Derive final AES key
        aes_key = bytes(panel_key_half) + bytes(server_key_half)
        ctr_cipher = AES.new(aes_key, AES.MODE_CTR, nonce=b"", initial_value=iv)

        # Step 5: Build and send encrypted clip header (45 bytes)
        alarm_msg = build_alarm_message(args.receiver, args.line, args.account)
        image_data = _get_image_data(args)
        viq = 3 if getattr(args, "format", "jpeg") == "jpeg" else 1
        clip_header = build_clip_header(
            alarm_msg, len(image_data),
            clip_id=args.clip_id, zone=args.zone, camera=args.camera,
            viq_status=viq,
        )

        # Send encrypted clip header (first 45 bytes)
        encrypted_header = ctr_cipher.encrypt(bytes(clip_header[:V3_CLIP_HEADER_LEN]))
        writer.write(encrypted_header)
        await writer.drain()
        _LOGGER.info("V3-enc: sent encrypted clip header (%d bytes)", V3_CLIP_HEADER_LEN)

        # Step 6: Send encrypted alarm message
        encrypted_alarm = ctr_cipher.encrypt(alarm_msg)
        writer.write(encrypted_alarm)
        await writer.drain()
        _LOGGER.info("V3-enc: sent encrypted alarm message (%d bytes)", len(alarm_msg))

        # Step 7: Receive ACK (plain byte for V3)
        ack = await asyncio.wait_for(reader.readexactly(1), timeout=10)
        _LOGGER.info("V3-enc: received %s", RESPONSE_NAMES.get(ack[0], f"0x{ack[0]:02X}"))
        if ack[0] != VIDEO_ACK:
            return False, f"Clip header rejected: {RESPONSE_NAMES.get(ack[0], f'0x{ack[0]:02X}')}"

        # Step 8: Send encrypted image segments
        ok, detail = await _send_image_segments(
            reader, writer, image_data, args.segment_size,
            encrypt_fn=ctr_cipher.encrypt,
        )
        if not ok:
            return False, detail

        # Step 9: Send encrypted end marker
        encrypted_end = ctr_cipher.encrypt(bytes([VIDEO_READY]))
        writer.write(encrypted_end)
        await writer.drain()
        _LOGGER.info("V3-enc: sent encrypted end marker")

        return True, "V3 encrypted clip sent successfully"

    except asyncio.TimeoutError:
        return False, "Timeout"
    except Exception as e:
        _LOGGER.exception("V3-enc error")
        return False, str(e)
    finally:
        writer.close()
        await writer.wait_closed()


# ==================== V4 Encrypted ====================

async def test_v4_encrypted(args, aes_key: bytes) -> tuple[bool, str]:
    """Send a video clip using V4 encrypted protocol (AES/CBC).

    The Java video server uses a SINGLE continuous CBC cipher for the entire
    session: clip header → alarm → image segments → end marker. The encrypt
    and decrypt ciphers are initialized once and the CBC state carries over
    across all operations.
    """
    reader, writer = await asyncio.open_connection(args.host, args.video_port)
    try:
        # Step 1: Receive READY (plain, before encryption established)
        ready = await asyncio.wait_for(reader.readexactly(1), timeout=10)
        _LOGGER.info("V4: received %s", RESPONSE_NAMES.get(ready[0], f"0x{ready[0]:02X}"))
        if ready[0] != VIDEO_READY:
            return False, f"Expected READY(0x14), got 0x{ready[0]:02X}"

        # Step 2: Send 25-byte V4 header (plaintext ASCII)
        v4_header = (
            f"#40R{args.receiver:04X}L{args.line:04X}"
            f"A{args.account:06X}S0030"
        ).encode("ascii")
        writer.write(v4_header)
        await writer.drain()
        _LOGGER.info("V4: sent V4 header (%d bytes): %s", len(v4_header), v4_header.decode())

        # Step 3: Send 16-byte IV
        panel_iv = get_random_bytes(V4_IV_LEN)
        writer.write(panel_iv)
        await writer.drain()
        _LOGGER.info("V4: sent IV (%d bytes)", V4_IV_LEN)

        # CRC accumulator: tracks raw bytes for CRC computation
        crc_data = bytearray()
        crc_data.extend(v4_header)
        crc_data.extend(panel_iv)

        # Step 4: Build and encrypt 48-byte clip header
        alarm_msg = build_alarm_message(args.receiver, args.line, args.account)
        image_data = _get_image_data(args)
        viq = 3 if getattr(args, "format", "jpeg") == "jpeg" else 1
        clip_header_45 = build_clip_header(
            alarm_msg, len(image_data),
            clip_id=args.clip_id, zone=args.zone, camera=args.camera,
            viq_status=viq,
        )

        # Build 48-byte V4 clip header: 3 zero bytes + 45-byte standard header
        clip_header_48 = bytearray(V4_CLIP_HEADER_LEN)
        clip_header_48[0:3] = b"\x00\x00\x00"
        clip_header_48[3:48] = clip_header_45[:V3_CLIP_HEADER_LEN]

        _LOGGER.debug("V4: plaintext clip header[0:3]=%s byte[16]=0x%02X",
                       clip_header_48[0:3].hex(), clip_header_48[16])

        # Create continuous CBC ciphers (NO re-init after clip header).
        # Java server uses the same cipher instance for the entire session —
        # CBC state carries over from clip header to alarm to image segments.
        cbc_enc = AES.new(aes_key, AES.MODE_CBC, panel_iv)
        cbc_dec = AES.new(aes_key, AES.MODE_CBC, panel_iv)

        # Encrypt clip header (CBC state advances)
        encrypted_clip_header = cbc_enc.encrypt(bytes(clip_header_48))
        writer.write(encrypted_clip_header)
        await writer.drain()
        crc_data.extend(encrypted_clip_header)
        _LOGGER.info("V4: sent encrypted clip header (%d bytes)", V4_CLIP_HEADER_LEN)

        # Step 5: Send encrypted alarm message (padded to 16-byte boundary)
        # CBC state continues from clip header — no re-init
        padded_alarm_len = _get_padded_length(len(alarm_msg))
        padded_alarm = bytearray(padded_alarm_len)
        padded_alarm[: len(alarm_msg)] = alarm_msg
        encrypted_alarm = cbc_enc.encrypt(bytes(padded_alarm))
        writer.write(encrypted_alarm)
        await writer.drain()
        crc_data.extend(encrypted_alarm)
        _LOGGER.info("V4: sent encrypted alarm (%d bytes, padded from %d)", padded_alarm_len, len(alarm_msg))

        # Step 6: Send CRC field (plaintext)
        crc_value = _CRC_CALC.checksum(bytes(crc_data))
        crc_field = f"C{crc_value:04X}".encode("ascii")
        writer.write(crc_field)
        await writer.drain()
        _LOGGER.info("V4: sent CRC: %s", crc_field.decode())

        # Step 7: Receive encrypted ACK (16 bytes)
        # Server's encrypt cipher has its own CBC state (independent of decrypt)
        ack_raw = await asyncio.wait_for(reader.readexactly(16), timeout=10)
        ack_dec = cbc_dec.decrypt(ack_raw)
        _LOGGER.info("V4: received ACK: 0x%02X (%s)", ack_dec[0], RESPONSE_NAMES.get(ack_dec[0], "?"))
        if ack_dec[0] != VIDEO_ACK:
            return False, f"Clip rejected: {RESPONSE_NAMES.get(ack_dec[0], f'0x{ack_dec[0]:02X}')}"

        # Step 8: Send encrypted image segments (CBC state continues)
        ok, detail = await _send_image_segments(
            reader, writer, image_data, args.segment_size,
            encrypt_fn=cbc_enc.encrypt,
            decrypt_fn=cbc_dec.decrypt,
            is_v4=True,
        )
        if not ok:
            return False, detail

        # Step 9: Send encrypted end marker
        end_block = bytearray(16)
        end_block[0] = VIDEO_READY
        encrypted_end = cbc_enc.encrypt(bytes(end_block))
        writer.write(encrypted_end)
        await writer.drain()
        _LOGGER.info("V4: sent encrypted end marker")

        return True, "V4 encrypted clip sent successfully"

    except asyncio.TimeoutError:
        return False, "Timeout"
    except Exception as e:
        _LOGGER.exception("V4 error")
        return False, str(e)
    finally:
        writer.close()
        await writer.wait_closed()


# ==================== DH Key Exchange ====================

def _unscramble_key(scrambled: bytes) -> bytes:
    """Unscramble the 24-byte 3DES key received from the server."""
    return bytes(a ^ b for a, b in zip(scrambled, _KEY_XOR_MASK))


def _encrypt_3des(cipher, msg: str) -> bytes:
    """Pad to 8-byte boundary and encrypt with 3DES/ECB."""
    data = msg.encode()
    padding_len = 8 - len(data) % 8
    if padding_len < 8:
        data += b"\x00" * padding_len
    return cipher.encrypt(data)


async def do_dh_key_exchange(args) -> bytes | None:
    """Perform DH key exchange on supervision port to obtain AES key for V4.

    The Java NetRec server expects DHR as a V4-framed plaintext message
    (not 3DES encrypted). The V4 header provides the R/L/A identifiers,
    so no heartbeat is needed before DHR.

    Returns 32-byte AES key on success, None on failure.
    """
    _LOGGER.info("DH: connecting to supervision port %s:%d", args.host, args.supervision_port)
    reader, writer = await asyncio.open_connection(args.host, args.supervision_port)
    try:
        # Step 1: Receive scrambled 3DES key (handshake)
        scrambled_key = await asyncio.wait_for(reader.readexactly(24), timeout=10)
        server_iv = bytes(scrambled_key[:16])
        _LOGGER.info("DH: 3DES handshake OK, server_iv=%s", server_iv.hex()[:16])

        # Step 2: Send V4-framed DHR (plaintext, not 3DES encrypted)
        # Format: #40R{recv}L{line}A{acct}S{payload_len} + IV(16) + DHR(3) + CRC(5)
        # Use ASCII-safe IV (bytes 0x01-0x7F) to avoid Java's byte→String→byte
        # charset corruption in parseV4Header() where panelIV = m.group(5).getBytes()
        panel_iv = bytes([(b % 0x7E) + 1 for b in get_random_bytes(16)])
        dhr_payload = b"DHR"
        v4_header = (
            f"#40R{args.receiver:04X}L{args.line:04X}"
            f"A{args.account:06X}S{len(dhr_payload):04X}"
        ).encode("ascii")

        # CRC over header + IV + payload
        crc_data = v4_header + panel_iv + dhr_payload
        crc_value = _CRC_CALC.checksum(crc_data)
        crc_field = f"C{crc_value:04X}".encode("ascii")

        dhr_frame = v4_header + panel_iv + dhr_payload + crc_field
        writer.write(dhr_frame)
        await writer.drain()
        _LOGGER.info("DH: V4-framed DHR sent (%d bytes): %s...%s",
                      len(dhr_frame), v4_header.decode(), crc_field.decode())

        # Step 3: Receive DH parameters (length-prefixed ASN.1 DER)
        params_len_raw = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        params_len = struct.unpack(">H", params_len_raw)[0]
        params_data = await asyncio.wait_for(reader.readexactly(params_len), timeout=10)

        seq = DerSequence()
        seq.decode(params_data)
        p = int(seq[0])
        g = int(seq[1])
        _LOGGER.info("DH: params received (p=%d bits, g=%d)", p.bit_length(), g)

        # Step 4: Generate panel DH keypair, send public key (must be 256 bytes)
        rand_bytes = get_random_bytes(256)
        panel_private = int.from_bytes(rand_bytes, "big") % (p - 3) + 2
        panel_public = pow(g, panel_private, p)
        # Java server requires exactly 256 or 257 bytes
        panel_pub_bytes = panel_public.to_bytes(256, "big")
        writer.write(struct.pack(">H", len(panel_pub_bytes)) + panel_pub_bytes)
        await writer.drain()
        _LOGGER.info("DH: panel public key sent (%d bytes)", len(panel_pub_bytes))

        # Step 5: Receive server public key
        server_key_len = struct.unpack(">H", await reader.readexactly(2))[0]
        server_pub_bytes = await asyncio.wait_for(
            reader.readexactly(server_key_len), timeout=10
        )
        server_public = int.from_bytes(server_pub_bytes, "big")
        _LOGGER.info("DH: server public key received (%d bytes)", server_key_len)

        # Step 6: Compute shared secret and derive AES key
        shared_int = pow(server_public, panel_private, p)
        # Pad to DH modulus size (256 bytes for 2048-bit) to match Java's
        # KeyAgreement.generateSecret() which always returns fixed-length output
        dh_byte_len = (p.bit_length() + 7) // 8
        shared_bytes = shared_int.to_bytes(dh_byte_len, "big")
        aes_key = shared_bytes[:32]
        _LOGGER.info("DH: AES key derived (%s...)", aes_key.hex()[:16])

        # Step 7: Send AES/CBC encrypted ACK with mixed IV
        # Java server uses mixed IV: even bytes from server, odd from panel
        mixed_iv = bytearray(16)
        for i in range(16):
            mixed_iv[i] = server_iv[i] if i % 2 == 0 else panel_iv[i]
        mixed_iv = bytes(mixed_iv)

        ack_data = b"ACK\r" + b"\x00" * 12
        ack_cipher = AES.new(aes_key, AES.MODE_CBC, mixed_iv)
        writer.write(ack_cipher.encrypt(ack_data))
        await writer.drain()
        _LOGGER.info("DH: AES/CBC ACK sent — key exchange complete")

        return aes_key

    except asyncio.TimeoutError:
        _LOGGER.error("DH: timeout")
        return None
    except Exception as e:
        _LOGGER.exception("DH error")
        return None
    finally:
        writer.close()
        await writer.wait_closed()


# ==================== Image Data ====================

def _generate_test_jpeg(width: int = 320, height: int = 240, label: str = "TEST") -> bytes:
    """Generate a JPEG test image with a colored pattern and label text."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        _LOGGER.warning("Pillow not installed — using minimal JPEG header + padding")
        return _generate_minimal_jpeg()

    img = Image.new("RGB", (width, height))
    draw = ImageDraw.Draw(img)

    # Draw colored stripes as a recognizable test pattern
    colors = [
        (255, 0, 0), (0, 255, 0), (0, 0, 255),
        (255, 255, 0), (0, 255, 255), (255, 0, 255),
        (255, 255, 255), (0, 0, 0),
    ]
    stripe_h = height // len(colors)
    for i, color in enumerate(colors):
        y0 = i * stripe_h
        y1 = (i + 1) * stripe_h if i < len(colors) - 1 else height
        draw.rectangle([0, y0, width, y1], fill=color)

    # Add label text in center
    try:
        font = ImageFont.truetype("arial.ttf", 24)
    except (OSError, IOError):
        font = ImageFont.load_default()

    ts = f"{label} {time.strftime('%H:%M:%S')}"
    bbox = draw.textbbox((0, 0), ts, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (width - tw) // 2
    ty = (height - th) // 2
    # Draw text with outline for visibility
    for dx, dy in [(-1, -1), (-1, 1), (1, -1), (1, 1)]:
        draw.text((tx + dx, ty + dy), ts, fill=(0, 0, 0), font=font)
    draw.text((tx, ty), ts, fill=(255, 255, 255), font=font)

    import io
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=80)
    return buf.getvalue()


def _generate_minimal_jpeg() -> bytes:
    """Fallback: JPEG SOI marker + padding for protocol testing."""
    header = b"\xff\xd8\xff\xe0"  # SOI + APP0 marker
    header += b"\x00\x10"         # APP0 length = 16
    header += b"JFIF\x00"         # JFIF identifier
    header += b"\x01\x01\x00"     # Version 1.1, no aspect
    header += b"\x00\x01\x00\x01" # Density 1x1
    header += b"\x00\x00"         # No thumbnail
    return header + b"\x00" * (4096 - len(header)) + b"\xff\xd9"


def _generate_test_asf(size: int = 32768) -> bytes:
    """Generate minimal ASF (Advanced Streaming Format) test data.

    Creates a valid ASF header structure followed by test payload data.
    """
    # ASF Header Object GUID
    asf_header_guid = bytes([
        0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11,
        0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
    ])
    # ASF Data Object GUID
    asf_data_guid = bytes([
        0x36, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11,
        0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
    ])

    # Build minimal header object (GUID + size + num_objects + reserved)
    header_body = struct.pack("<I", 0)  # 0 header objects
    header_body += b"\x01\x02"          # reserved bytes
    header_size = 16 + 8 + len(header_body)  # GUID + size field + body
    header_obj = asf_header_guid + struct.pack("<Q", header_size) + header_body

    # Build data object with test payload
    payload_size = max(0, size - len(header_obj) - 16 - 8 - 16)
    # Data object GUID: total_packets(8) + reserved(2) + payload
    data_body = struct.pack("<Q", 1)   # total packets = 1
    data_body += b"\x01\x01"           # reserved
    data_body += bytes(range(256)) * (payload_size // 256 + 1)
    data_body = data_body[:payload_size]
    data_size = 16 + 8 + len(data_body)
    data_obj = asf_data_guid + struct.pack("<Q", data_size) + data_body

    return header_obj + data_obj


def _get_image_data(args) -> bytes:
    """Load image data from file, directory, or generate test images."""
    if args.image_file:
        p = Path(args.image_file)
        if p.is_dir():
            # Concatenate all image files in the directory
            images = sorted(p.glob("*"))
            images = [f for f in images if f.suffix.lower() in (
                ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".asf", ".avi", ".mp4",
            )]
            if not images:
                _LOGGER.warning("No image files found in %s, using test JPEG", p)
                return _generate_test_jpeg(label="CAM1")
            data = bytearray()
            for img_path in images:
                data.extend(img_path.read_bytes())
                _LOGGER.info("  loaded %s (%d bytes)", img_path.name, img_path.stat().st_size)
            return bytes(data)
        else:
            data = p.read_bytes()
            _LOGGER.info("  loaded %s (%d bytes)", p.name, len(data))
            return data

    # Default: generate test data based on format
    fmt = getattr(args, "format", "jpeg")
    if fmt == "asf":
        return _generate_test_asf(size=args.image_size)

    num_images = getattr(args, "num_images", 1)
    if num_images == 1:
        return _generate_test_jpeg(label=f"CAM{args.camera}")
    data = bytearray()
    for i in range(num_images):
        data.extend(_generate_test_jpeg(label=f"IMG{i + 1}"))
    return bytes(data)


# ==================== Local Key Persistence ====================

_KEYSTORE_FILE = Path(__file__).parent / "video_test_keys.json"


def _load_stored_key(account: int) -> bytes | None:
    """Load a previously stored AES key for an account."""
    if not _KEYSTORE_FILE.exists():
        return None
    try:
        data = json.loads(_KEYSTORE_FILE.read_text())
        hex_key = data.get(f"{account:06X}")
        if hex_key:
            return bytes.fromhex(hex_key)
    except (json.JSONDecodeError, OSError, ValueError):
        pass
    return None


def _save_key(account: int, key: bytes) -> None:
    """Save an AES key for an account."""
    data = {}
    if _KEYSTORE_FILE.exists():
        try:
            data = json.loads(_KEYSTORE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    data[f"{account:06X}"] = key.hex().upper()
    _KEYSTORE_FILE.write_text(json.dumps(data, indent=2))


# ==================== Main ====================

async def main():
    parser = argparse.ArgumentParser(description="OH video test client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--supervision-port", type=int, default=8991)
    parser.add_argument("--video-port", type=int, default=9995)
    parser.add_argument("--account", type=lambda x: int(x, 0), default=0x001234)
    parser.add_argument("--receiver", type=lambda x: int(x, 0), default=0x6666)
    parser.add_argument("--line", type=lambda x: int(x, 0), default=0x1234)
    parser.add_argument("--protocol", choices=["v3", "v3-enc", "v4", "all"], default="all")
    parser.add_argument("--aes-key", help="Pre-shared AES key (hex) for V4, skips DH")
    parser.add_argument("--force-dh", action="store_true", help="Force new DH exchange (ignore stored key)")
    parser.add_argument("--panel-serial", default="001234")
    parser.add_argument("--panel-id", type=lambda x: int(x, 0), default=0x2F96C533)
    parser.add_argument("--format", choices=["jpeg", "asf"], default="jpeg",
                        help="Clip format: jpeg (viq_status=3) or asf video (viq_status=1)")
    parser.add_argument("--image-file", help="Path to image/video file or directory")
    parser.add_argument("--image-size", type=int, default=4096)
    parser.add_argument("--num-images", type=int, default=1, help="Number of test images per clip (default: 1)")
    parser.add_argument("--segment-size", type=int, default=DEFAULT_SEGMENT_SIZE)
    parser.add_argument("--clip-id", type=int, default=1)
    parser.add_argument("--camera", type=int, default=1)
    parser.add_argument("--zone", type=int, default=1)
    args = parser.parse_args()

    results = []

    # V3 Unencrypted
    if args.protocol in ("v3", "all"):
        print(f"\n{'='*60}")
        print("TEST: V3 Unencrypted Video Clip")
        print(f"{'='*60}")
        ok, detail = await test_v3_unencrypted(args)
        print(f"  {'PASS' if ok else 'FAIL'}: {detail}")
        results.append(("V3 Unencrypted", ok))

    # V3 Encrypted
    if args.protocol in ("v3-enc", "all"):
        print(f"\n{'='*60}")
        print("TEST: V3 Encrypted Video Clip")
        print(f"{'='*60}")
        ok, detail = await test_v3_encrypted(args)
        print(f"  {'PASS' if ok else 'FAIL'}: {detail}")
        results.append(("V3 Encrypted", ok))

    # V4 Encrypted
    if args.protocol in ("v4", "all"):
        print(f"\n{'='*60}")
        print("TEST: V4 Encrypted Video Clip")
        print(f"{'='*60}")
        aes_key = None
        if args.aes_key:
            aes_key = bytes.fromhex(args.aes_key)
            _LOGGER.info("V4: using pre-shared AES key from --aes-key")
        else:
            # Try locally stored key first (unless --force-dh)
            if not args.force_dh:
                aes_key = _load_stored_key(args.account)
                if aes_key:
                    _LOGGER.info("V4: using stored AES key from %s", _KEYSTORE_FILE.name)
            if aes_key is None:
                _LOGGER.info("V4: performing DH key exchange on supervision port")
                aes_key = await do_dh_key_exchange(args)
                if aes_key:
                    _save_key(args.account, aes_key)
                    _LOGGER.info("V4: AES key saved to %s", _KEYSTORE_FILE.name)
                    # Small delay to let server commit the key to DB
                    await asyncio.sleep(0.5)

        if aes_key:
            ok, detail = await test_v4_encrypted(args, aes_key)
            print(f"  {'PASS' if ok else 'FAIL'}: {detail}")
            results.append(("V4 Encrypted", ok))
        else:
            print("  SKIP: Could not obtain AES key (DH failed or no --aes-key)")
            results.append(("V4 Encrypted", False))

    # Summary
    print(f"\n{'='*60}")
    print("RESULTS SUMMARY")
    print(f"{'='*60}")
    passed = sum(1 for _, p in results if p)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n  {passed}/{len(results)} passed")
    print(f"{'='*60}")

    return all(p for _, p in results)


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
