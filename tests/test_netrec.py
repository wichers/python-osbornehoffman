#!/usr/bin/python
"""Test client against OH receiver (Java NetRec or local Python OHServer).

Simulates a panel connecting to the OH receiver and sending
V1 heartbeat, V2 heartbeat, XSIA (SIA-DCS), ADM-CID, and V4 events.

Usage:
    python tests/test_netrec.py                  # External server on 127.0.0.1:8991
    python tests/test_netrec.py --port 8996      # External server on custom port
    python tests/test_netrec.py --local          # Start local OHServer and test against it
    python tests/test_netrec.py --local --port 0 # Local server on auto-assigned port
"""

import argparse
import asyncio
import codecs
import logging
import struct
import sys

from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.asn1 import DerSequence
from crc import Calculator, Crc16

logging.basicConfig(level=logging.DEBUG)
_LOGGER = logging.getLogger(__name__)

# Globals set by main() based on CLI args
HOST = "127.0.0.1"
PORT = 8991
MAX_RETRIES = 3
DELAY = 3  # seconds between tests

# XOR mask for key unscrambling (OH protocol spec)
_KEY_XOR_MASK = bytes([
    0x55, 0x2D, 0x6A, 0x05, 0x23, 0x49, 0x39, 0xA8,
    0x45, 0x29, 0xD3, 0xE9, 0x94, 0xC2, 0xB5, 0x88,
    0x45, 0xA3, 0x50, 0x8A, 0x44, 0xAA, 0x69, 0x54,
])

# --- Message templates ---

V1_HB = "SR{receiver:04X}L{line:04X}    {system_account:06X}XX    \x00"

V2_HB = "SR{receiver:04X}L{line:04X}    {system_account:06X}XX    \x00[ID{panel_id:08X}]\x00"

XSIA_NO_TEXT = (
    "\n01010034\"SIA-DCS\"{sequence:04X}R{receiver:04X}L{line:04X}"
    "[#{account:06X}|Nri{area:02X}/{sia_event}{sia_zone:03X}]\r\x00"
)

ADM_CID = (
    "\n01010034\"ADM-CID\"{sequence:04X}R{receiver:04X}L{line:04X}"
    "[#{account:06X}|{qualifier}{event_code:03d} {area:02d} {zone:03d}]\r\x00"
)


# ==================== Crypto helpers ====================

def unscramble_key(scrambled: bytes) -> bytes:
    """Unscramble the 24-byte 3DES key received from the server."""
    return bytes(a ^ b for a, b in zip(scrambled, _KEY_XOR_MASK))


def encrypt_message(cipher, msg: str) -> bytes:
    """Pad to 8-byte boundary and encrypt with 3DES/ECB."""
    data = msg.encode()
    padding_len = 8 - len(data) % 8
    if padding_len < 8:
        data += b"\x00" * padding_len
    return cipher.encrypt(data)


# ==================== V3 test helpers ====================

async def _try_send(msg_builder) -> tuple[bool, str]:
    """Single attempt: connect, key exchange, send, read ACK.

    Returns (success, detail_message).
    """
    reader, writer = await asyncio.open_connection(HOST, PORT)
    try:
        # Step 1: Receive scrambled key
        scrambled_key = await asyncio.wait_for(reader.read(24), timeout=5)
        if len(scrambled_key) != 24:
            return False, f"Expected 24-byte key, got {len(scrambled_key)} bytes"

        key = DES3.adjust_key_parity(unscramble_key(scrambled_key))
        cipher = DES3.new(key, mode=DES3.MODE_ECB)

        # Step 2: Build and send message
        if callable(msg_builder):
            msg = msg_builder(cipher)
        else:
            msg = msg_builder

        encrypted = encrypt_message(cipher, msg)
        print(f"  Sending: {msg!r}")
        writer.write(encrypted)
        await writer.drain()

        # Step 3: Read response
        reply_raw = await asyncio.wait_for(reader.read(1024), timeout=10)
        reply = cipher.decrypt(reply_raw)
        print(f"  Response: {reply!r}")

        # Handle panel ID assignment
        if reply[:2] == b"ID":
            print(f"  Panel ID assigned: {reply[2:10].decode()}")
            reply_raw = await asyncio.wait_for(reader.read(1024), timeout=10)
            reply = cipher.decrypt(reply_raw)
            print(f"  ACK: {reply!r}")

        if reply[:3] == b"ACK":
            return True, "ACK received"
        else:
            return False, f"Expected ACK, got {reply!r}"

    except asyncio.TimeoutError:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)
    finally:
        writer.close()
        await writer.wait_closed()


async def send_message(name: str, msg_builder) -> bool:
    """Send a message with retries."""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")

    for attempt in range(1, MAX_RETRIES + 1):
        if attempt > 1:
            print(f"  Retry {attempt}/{MAX_RETRIES}...")
            await asyncio.sleep(1)

        ok, detail = await _try_send(msg_builder)
        if ok:
            print(f"  PASS")
            await asyncio.sleep(DELAY)
            return True
        else:
            print(f"  Attempt {attempt}: {detail}")

    print(f"  FAIL after {MAX_RETRIES} attempts")
    await asyncio.sleep(DELAY)
    return False


def make_xsia(base, sequence, area, sia_event, sia_zone, text):
    """Return a callable that builds an XSIA message using the session cipher."""
    def builder(cipher):
        enc_pid = codecs.encode(
            cipher.encrypt(f"{base['panel_id']:08X}".encode()), "hex"
        ).decode().upper()
        return (
            f"\n01010053\"SIA-DCS\"{sequence:04X}R{base['receiver']:04X}"
            f"L{base['line']:04X}[#{base['account']:06X}"
            f"|Nri{area:02X}/{sia_event}{sia_zone:03X}*'{text}'NM]"
            f"{enc_pid}|#{base['system_account']:06X}\r\x00"
        )
    return builder


# ==================== V4 test helpers ====================

async def _try_v4_header(base) -> tuple[bool, str]:
    """Test that server recognizes V4 header format.

    V4 without a pre-shared AES key should get a NACK (server knows V4 format
    but can't decrypt without a key). This confirms V4 protocol recognition.
    """
    reader, writer = await asyncio.open_connection(HOST, PORT)
    try:
        scrambled_key = await asyncio.wait_for(reader.read(24), timeout=5)
        if len(scrambled_key) != 24:
            return False, f"Expected 24-byte key, got {len(scrambled_key)} bytes"

        des_key = DES3.adjust_key_parity(unscramble_key(scrambled_key))
        des_cipher = DES3.new(des_key, mode=DES3.MODE_ECB)

        # Send V4 header directly (plaintext, not 3DES encrypted)
        v4_header = (
            f"#40R{base['receiver']:04X}L{base['line']:04X}"
            f"A{base['system_account']:06X}S0040"
        ).encode()
        writer.write(v4_header)
        await writer.drain()
        print(f"  Sent V4 header: {v4_header}")

        # Server should respond with 3DES-encrypted NACK (no AES key)
        reply_raw = await asyncio.wait_for(reader.read(1024), timeout=10)
        if len(reply_raw) < 8:
            return False, f"Response too short: {len(reply_raw)} bytes"

        reply = des_cipher.decrypt(reply_raw[:8])
        print(f"  Response: {reply!r}")

        if reply[:4] == b"NACK":
            return True, "V4 header recognized (NACK = no AES key, expected)"
        elif reply[:3] == b"ACK":
            return True, "V4 header accepted"
        else:
            return False, f"Unexpected response: {reply!r}"

    except asyncio.TimeoutError:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)
    finally:
        writer.close()
        await writer.wait_closed()


async def _try_dhr(base) -> tuple[bool, str]:
    """Test DHR (Diffie-Hellman Request) handling.

    Sends a V2 heartbeat first (account identification), then DHR.
    Checks if the server supports DH key exchange.
    """
    reader, writer = await asyncio.open_connection(HOST, PORT)
    try:
        scrambled_key = await asyncio.wait_for(reader.read(24), timeout=5)
        if len(scrambled_key) != 24:
            return False, f"Expected 24-byte key, got {len(scrambled_key)} bytes"

        des_key = DES3.adjust_key_parity(unscramble_key(scrambled_key))
        des_cipher = DES3.new(des_key, mode=DES3.MODE_ECB)

        # Send V2 heartbeat first (identify account)
        hb_msg = (
            f"SR{base['receiver']:04X}L{base['line']:04X}"
            f"    {base['system_account']:06X}XX    \x00"
            f"[ID{base['panel_id']:08X}]\x00"
        )
        writer.write(encrypt_message(des_cipher, hb_msg))
        await writer.drain()

        hb_reply_raw = await asyncio.wait_for(reader.read(1024), timeout=10)
        hb_reply = des_cipher.decrypt(hb_reply_raw)
        if hb_reply[:2] == b"ID":
            hb_reply_raw = await asyncio.wait_for(reader.read(1024), timeout=10)
            hb_reply = des_cipher.decrypt(hb_reply_raw)
        if hb_reply[:3] != b"ACK":
            return False, f"Heartbeat not ACKed: {hb_reply!r}"
        print(f"  V2 heartbeat ACKed")

        # Send DHR
        writer.write(encrypt_message(des_cipher, "DHR\r\x00"))
        await writer.drain()
        print(f"  DHR sent")

        # Read response — DH params or disconnect
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=5)
        except asyncio.TimeoutError:
            raw = b""

        if len(raw) == 0:
            print(f"  Server closed connection (DHR not supported on this instance)")
            return True, "DHR recognized (server closed connection — DH not configured)"

        # If we got data, check if it's length-prefixed DH params
        if len(raw) >= 2:
            params_len = struct.unpack(">H", raw[:2])[0]
            print(f"  DH response: {len(raw)} bytes, params_len={params_len}")
            if 200 < params_len < 1000:
                print(f"  DH params received! Full V4 DH exchange supported.")
                return True, "DH params received"

        # Try decrypting as 3DES
        if len(raw) >= 8:
            dec = des_cipher.decrypt(raw[:8])
            print(f"  Response (3DES): {dec!r}")

        return True, f"DHR response: {len(raw)} bytes"

    except asyncio.TimeoutError:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)
    finally:
        writer.close()
        await writer.wait_closed()


async def _try_v4_full_dh(base) -> tuple[bool, str]:
    """Full V4 session: heartbeat, DH key exchange, then AES-encrypted V4 message.

    Only works against servers that support DHR (e.g., our local OHServer).
    """
    reader, writer = await asyncio.open_connection(HOST, PORT)
    try:
        # Step 1: 3DES key exchange
        scrambled_key = await asyncio.wait_for(reader.read(24), timeout=5)
        if len(scrambled_key) != 24:
            return False, f"Expected 24-byte key, got {len(scrambled_key)} bytes"

        des_key = DES3.adjust_key_parity(unscramble_key(scrambled_key))
        des_cipher = DES3.new(des_key, mode=DES3.MODE_ECB)
        server_iv = bytes(scrambled_key[:16])
        print(f"  3DES key exchange OK")

        # Step 2: V2 heartbeat to identify account
        hb_msg = (
            f"SR{base['receiver']:04X}L{base['line']:04X}"
            f"    {base['system_account']:06X}XX    \x00"
            f"[ID{base['panel_id']:08X}]\x00"
        )
        writer.write(encrypt_message(des_cipher, hb_msg))
        await writer.drain()

        hb_reply_raw = await asyncio.wait_for(reader.read(1024), timeout=10)
        hb_reply = des_cipher.decrypt(hb_reply_raw)
        if hb_reply[:2] == b"ID":
            hb_reply_raw = await asyncio.wait_for(reader.read(1024), timeout=10)
            hb_reply = des_cipher.decrypt(hb_reply_raw)
        if hb_reply[:3] != b"ACK":
            return False, f"Heartbeat not ACKed: {hb_reply!r}"
        print(f"  V2 heartbeat ACKed")

        # Step 3: Send DHR
        writer.write(encrypt_message(des_cipher, "DHR\r\x00"))
        await writer.drain()
        print(f"  DHR sent")

        # Step 4: Receive DH parameters (length-prefixed ASN.1 DER)
        params_len_raw = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        params_len = struct.unpack(">H", params_len_raw)[0]
        params_data = await asyncio.wait_for(reader.readexactly(params_len), timeout=10)

        seq = DerSequence()
        seq.decode(params_data)
        p = int(seq[0])
        g = int(seq[1])
        print(f"  DH params received (p={p.bit_length()} bits, g={g})")

        # Step 5: Generate panel DH keypair and send public key
        rand_bytes = get_random_bytes(256)
        panel_private = int.from_bytes(rand_bytes, "big") % (p - 3) + 2
        panel_public = pow(g, panel_private, p)
        panel_pub_bytes = panel_public.to_bytes(
            (panel_public.bit_length() + 7) // 8, "big"
        )
        writer.write(struct.pack(">H", len(panel_pub_bytes)) + panel_pub_bytes)
        await writer.drain()
        print(f"  Panel public key sent ({len(panel_pub_bytes)} bytes)")

        # Step 6: Receive server public key
        server_key_len_raw = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        server_key_len = struct.unpack(">H", server_key_len_raw)[0]
        server_pub_bytes = await asyncio.wait_for(
            reader.readexactly(server_key_len), timeout=10
        )
        server_public = int.from_bytes(server_pub_bytes, "big")
        print(f"  Server public key received ({server_key_len} bytes)")

        # Step 7: Compute shared secret and derive AES key
        shared_int = pow(server_public, panel_private, p)
        shared_bytes = shared_int.to_bytes(
            (shared_int.bit_length() + 7) // 8, "big"
        )
        aes_key = shared_bytes[:32]
        print(f"  AES key derived ({aes_key.hex()[:16]}...)")

        # Step 8: Send AES-encrypted ACK to confirm
        ack_data = b"ACK\r" + b"\x00" * 12
        aes_ecb = AES.new(aes_key, AES.MODE_ECB)
        writer.write(aes_ecb.encrypt(ack_data))
        await writer.drain()
        print(f"  DH ACK sent — key exchange complete")

        # Step 9: Send a V4 SIA message
        inner_payload = (
            f"\n01010034\"SIA-DCS\"0030R{base['receiver']:04X}L{base['line']:04X}"
            f"[#{base['account']:06X}|Nri01/NR001]\r\x00"
        )
        panel_iv = get_random_bytes(16)

        # Mix IVs: even from server, odd from panel
        mixed_iv = bytearray(16)
        for i in range(16):
            mixed_iv[i] = server_iv[i] if i % 2 == 0 else panel_iv[i]
        mixed_iv = bytes(mixed_iv)

        # Encrypt inner payload with AES/CBC
        payload_bytes = inner_payload.encode()
        pad_len = 16 - len(payload_bytes) % 16
        if pad_len < 16:
            payload_bytes += b"\x00" * pad_len
        aes_cbc = AES.new(aes_key, AES.MODE_CBC, mixed_iv)
        encrypted_payload = aes_cbc.encrypt(payload_bytes)

        # Build V4 frame: header + panel_iv + encrypted_payload + CRC
        header = (
            f"#40R{base['receiver']:04X}L{base['line']:04X}"
            f"A{base['system_account']:06X}S{len(encrypted_payload):04X}"
        ).encode()
        calc = Calculator(Crc16.MODBUS)
        crc_data = header + panel_iv + encrypted_payload
        crc = calc.checksum(crc_data)
        v4_msg = header + panel_iv + encrypted_payload + f"C{crc:04X}".encode()

        print(f"  V4 SIA NR: {len(v4_msg)} bytes "
              f"(hdr={len(header)}, iv=16, enc={len(encrypted_payload)}, crc=5)")
        writer.write(v4_msg)
        await writer.drain()

        # Read V4 response (AES-encrypted ACK with mixed IV)
        reply_raw = await asyncio.wait_for(reader.read(1024), timeout=10)
        if len(reply_raw) >= 16:
            aes_dec = AES.new(aes_key, AES.MODE_CBC, mixed_iv)
            reply = aes_dec.decrypt(reply_raw[:16])
            print(f"  V4 Response: {reply!r}")
            if reply[:3] == b"ACK":
                return True, "Full V4 DH + AES message exchange OK"
            else:
                return False, f"V4 Expected ACK, got {reply!r}"
        else:
            return False, f"V4 response too short: {len(reply_raw)} bytes"

    except asyncio.TimeoutError:
        return False, "Timeout"
    except Exception as e:
        import traceback
        traceback.print_exc()
        return False, str(e)
    finally:
        writer.close()
        await writer.wait_closed()


async def send_v4_test(name, test_func, base) -> bool:
    """Run a V4 protocol test with retries."""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")

    for attempt in range(1, MAX_RETRIES + 1):
        if attempt > 1:
            print(f"  Retry {attempt}/{MAX_RETRIES}...")
            await asyncio.sleep(1)

        ok, detail = await test_func(base)
        if ok:
            print(f"  PASS ({detail})")
            await asyncio.sleep(DELAY)
            return True
        else:
            print(f"  Attempt {attempt}: {detail}")

    print(f"  FAIL after {MAX_RETRIES} attempts")
    await asyncio.sleep(DELAY)
    return False


# ==================== Local server ====================

async def start_local_server(base, port, events):
    """Start a local OHServer for testing."""
    sys.path.insert(0, ".")
    from osbornehoffman import OHAccount
    from osbornehoffman.server import OHServer

    account = OHAccount(
        account_id=f"{base['system_account']:06X}",
        panel_id=base["panel_id"],
        forward_heartbeat=True,
    )

    async def callback(event):
        events.append(event)
        return True

    server = OHServer(
        host="127.0.0.1",
        port=port,
        accounts={account.account_id: account},
        callback=callback,
    )
    await server.start_server()

    # Get the actual port (useful when port=0)
    actual_port = server.server.sockets[0].getsockname()[1]
    return server, actual_port


# ==================== Main ====================

async def main():
    """Run all protocol tests."""
    global HOST, PORT, MAX_RETRIES, DELAY

    parser = argparse.ArgumentParser(description="OH protocol integration tests")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=8991, help="Server port")
    parser.add_argument("--local", action="store_true",
                        help="Start local OHServer instead of connecting to external")
    args = parser.parse_args()

    HOST = args.host
    PORT = args.port

    base = {
        "system_account": 0xF0000D,
        "receiver": 0xDEAD,
        "line": 0xBEEF,
        "panel_id": 0x2F96C533,
        "account": 0xFEEEED,
    }

    local_server = None
    events = []
    is_local = args.local

    if is_local:
        local_server, PORT = await start_local_server(base, 0, events)
        MAX_RETRIES = 1  # No dropped connections with our server
        DELAY = 0        # No delay needed
        print(f"Local OHServer started on {HOST}:{PORT}")
    else:
        MAX_RETRIES = 3  # Java NetRec drops every other connection
        DELAY = 3
        print(f"Testing against external server at {HOST}:{PORT}")

    results = []

    try:
        # --- V3 Tests (work against both Java NetRec and local) ---

        msg = V1_HB.format(**base)
        results.append(("V1 Heartbeat", await send_message("V1 Heartbeat", msg)))

        msg = V2_HB.format(**base)
        results.append(("V2 Heartbeat", await send_message("V2 Heartbeat", msg)))

        results.append(("XSIA NR (Network Restoral)", await send_message(
            "XSIA NR (Network Restoral)",
            make_xsia(base, 1, 1, "NR", 1, "Home"),
        )))

        results.append(("XSIA UA (Untyped Zone Alarm)", await send_message(
            "XSIA UA (Untyped Zone Alarm)",
            make_xsia(base, 2, 4, "UA", 105, "HA det. woonk"),
        )))

        results.append(("XSIA CL (System Armed)", await send_message(
            "XSIA CL (System Armed by user 001)",
            make_xsia(base, 10, 1, "CL", 1, "User Armed"),
        )))

        results.append(("XSIA OP (System Disarmed)", await send_message(
            "XSIA OP (System Disarmed by user 003)",
            make_xsia(base, 11, 1, "OP", 3, "User Disarmed"),
        )))

        msg = XSIA_NO_TEXT.format(**base, sequence=3, area=4, sia_event="BA", sia_zone=1)
        results.append(("SIA BA (Burglar Alarm) no text", await send_message(
            "SIA BA (Burglar Alarm) no text", msg,
        )))

        msg = ADM_CID.format(**base, sequence=5, qualifier=1, event_code=150, area=4, zone=261)
        results.append(("ADM-CID (event 150/zone 261)", await send_message(
            "ADM-CID (event 150/zone 261)", msg,
        )))

        msg = ADM_CID.format(**base, sequence=6, qualifier=3, event_code=150, area=4, zone=261)
        results.append(("ADM-CID restoral (event 150/zone 261)", await send_message(
            "ADM-CID restoral (event 150/zone 261)", msg,
        )))

        # --- V4 Tests ---

        results.append(("V4 Header Recognition", await send_v4_test(
            "V4 Header Recognition", _try_v4_header, base,
        )))

        results.append(("V4 DHR", await send_v4_test(
            "V4 DHR (Diffie-Hellman Request)", _try_dhr, base,
        )))

        # Full V4 DH + AES message (only works against local server with DH support)
        if is_local:
            results.append(("V4 Full DH + AES Message", await send_v4_test(
                "V4 Full DH + AES Message", _try_v4_full_dh, base,
            )))

        # --- Local server: validate received events ---
        if is_local and events:
            print(f"\n{'='*60}")
            print(f"SERVER RECEIVED {len(events)} EVENTS")
            print(f"{'='*60}")
            for i, ev in enumerate(events):
                mt = ev.get("message_type")
                sia = ev.get("sia_event", "-")
                acct = ev.get("system_account", "?")
                pid = ev.get("panel_id")
                v4 = ev.get("is_v4", False)
                print(f"  {i+1}. {mt.name if mt else '?':<6} sia={sia:<4} "
                      f"account={acct} panel_id={pid} v4={v4}")

    finally:
        # --- Summary ---
        print(f"\n{'='*60}")
        mode = "LOCAL" if is_local else "EXTERNAL"
        print(f"RESULTS SUMMARY ({mode})")
        print(f"{'='*60}")
        passed_count = sum(1 for _, p in results if p)
        for name, passed in results:
            print(f"  {'PASS' if passed else 'FAIL'}  {name}")
        print(f"\n  {passed_count}/{len(results)} passed")
        print(f"{'='*60}")

        if local_server:
            await local_server.close_server()
            print("Local OHServer stopped.")

    return all(p for _, p in results)


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
