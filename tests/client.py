#!/usr/bin/python
"""Run a test client."""
import asyncio
import json
import logging
import codecs
import sys
import base64
from Crypto.Cipher import DES3

params = {
    "system_account": 0xF0000D,
    "receiver": 0xDEAD,
    "line": 0xBEEF,
    "panel_id": 798334515,
    "account": 0xFEEEED,
    "sia_event": "RS",
}

v1_hb = "SR{receiver:04X}L{line:04X}    {system_account:06X}XX    \x00"
v2_hb = "SR{receiver:04X}L{line:04X}    {system_account:06X}XX    \x00[ID{panel_id:08X}]\x00"
xsia = "\n01010053\"SIA-DCS\"{sequence:04X}R{receiver:04X}L{line:04X}[#{account:06X}|Nri01/{sia_event}001*'TEST'NM]{panel_id}|#{system_account:06X}\r\x00"
xsia = "\n0101005E\"SIA-DCS\"{sequence:04X}R{receiver:04X}L{line:04X}[#{account:06X}|Nri01/{sia_event}001*'HA det. woonk'NM]{panel_id}|#{system_account:06X}\r\x00"
xsia = "\n01010050\"SIA-DCS\"{sequence:04X}R{receiver:04X}L{line:04X}[#{account:06X}|Nri01/{sia_event}0000*'Home'NM]{panel_id}|#{system_account:06X}\r\x00"

# Decrypted data: b'\n01010053"SIA-DCS"0001R6666L1234[#001234|Nri01/NR001*\'HA\'NM]E69B557E0CE8BD98|#001234\r\x00\x00\x00'
# 'sequence': '0001', 'receiver': '6666', 'line': '1234', 'account': '001234', 'qualifier': 'N', 'area': '01', 'event_code': 'NR001', 'sia_event': 'NR', 'sia_code': '001', 'text': 'HA', 'panel_id': 57005, 'system_account': '001234', 'timestamp': None, 'message_type': <MessageType.SIA: 1>, 'encrypted_ack': True, 'sia_type': 'Network Restoral', 'sia_description': 'A communications network has returned to normal operation', 'sia_concerns': 'Network number'}


# XSIA
# Decrypted data: b'\n01010053"SIA-DCS"0001R6666L1234[#001234|Nri01/NR001*\'HA\'NM]E69B557E0CE8BD98|#001234\r\x00\x00\x00'
# Event: {'peername': ('192.168.100.10', 22967), 'sequence': '0001', 'receiver': '6666', 'line': '1234', 'account': '001234', 'qualifier': 'N', 'area': '01', 'event_code': 'NR001', 'sia_event': 'NR', 'sia_code': '001', 'text': 'HA', 'panel_id': 57005, 'system_account': '001234', 'timestamp': None, 'message_type': <MessageType.SIA: 1>, 'encrypted_ack': True, 'sia_type': 'Network Restoral', 'sia_description': 'A communications network has returned to normal operation', 'sia_concerns': 'Network number'}
# Decrypted data: b'\n0101005E"SIA-DCS"0002R6666L1234[#005412|Nri04/UA105*\'HA det. woonk\'NM]E69B557E0CE8BD98|#001234\r\x00\x00\x00\x00\x00\x00\x00\x00'
# Event: {'peername': ('192.168.100.10', 22967), 'sequence': '0002', 'receiver': '6666', 'line': '1234', 'account': '005412', 'qualifier': 'N', 'area': '04', 'event_code': 'UA105', 'sia_event': 'UA', 'sia_code': '105', 'text': 'HA det. woonk', 'panel_id': 57005, 'system_account': '001234', 'timestamp': None, 'message_type': <MessageType.SIA: 1>, 'encrypted_ack': True, 'sia_type': 'Untyped Zone Alarm', 'sia_description': 'Alarm condition from zone of unknown type', 'sia_concerns': 'Zone or point'}
# Decrypted data: b'\n0101005E"SIA-DCS"0003R6666L1234[#005412|Nri04/UR105*\'HA det. woonk\'NM]E69B557E0CE8BD98|#001234\r\x00\x00\x00\x00\x00\x00\x00\x00'
# Event: {'peername': ('192.168.100.10', 22967), 'sequence': '0003', 'receiver': '6666', 'line': '1234', 'account': '005412', 'qualifier': 'N', 'area': '04', 'event_code': 'UR105', 'sia_event': 'UR', 'sia_code': '105', 'text': 'HA det. woonk', 'panel_id': 57005, 'system_account': '001234', 'timestamp': None, 'message_type': <MessageType.SIA: 1>, 'encrypted_ack': True, 'sia_type': 'Untyped Zone Restoral', 'sia_description': 'Alarm/trouble condition eliminated from zone of unknown type', 'sia_concerns': 'Zone or point'}
# Decrypted data: b'\n0101005F"SIA-DCS"0004R6666L1234[#005412|Nri04/UA103*\'HA det. keuken\'NM]E69B557E0CE8BD98|#001234\r\x00\x00\x00\x00\x00\x00\x00'
# Event: {'peername': ('192.168.100.10', 22967), 'sequence': '0004', 'receiver': '6666', 'line': '1234', 'account': '005412', 'qualifier': 'N', 'area': '04', 'event_code': 'UA103', 'sia_event': 'UA', 'sia_code': '103', 'text': 'HA det. keuken', 'panel_id': 57005, 'system_account': '001234', 'timestamp': None, 'message_type': <MessageType.SIA: 1>, 'encrypted_ack': True, 'sia_type': 'Untyped Zone Alarm', 'sia_description': 'Alarm condition from zone of unknown type', 'sia_concerns': 'Zone or point'}
# Decrypted data: b'\n0101005F"SIA-DCS"0005R6666L1234[#005412|Nri04/UR103*\'HA det. keuken\'NM]E69B557E0CE8BD98|#001234\r\x00\x00\x00\x00\x00\x00\x00'
# Event: {'peername': ('192.168.100.10', 22967), 'sequence': '0005', 'receiver': '6666', 'line': '1234', 'account': '005412', 'qualifier': 'N', 'area': '04', 'event_code': 'UR103', 'sia_event': 'UR', 'sia_code': '103', 'text': 'HA det. keuken', 'panel_id': 57005, 'system_account': '001234', 'timestamp': None, 'message_type': <MessageType.SIA: 1>, 'encrypted_ack': True, 'sia_type': 'Untyped Zone Restoral', 'sia_description': 'Alarm/trouble condition eliminated from zone of unknown type', 'sia_concerns': 'Zone or point'}
# Decrypted data: b'\n01010053"SIA-DCS"0006R6666L1234[#001234|Nri01/YK001*\'HA\'NM]E69B557E0CE8BD98|#001234\r\x00\x00\x00'
# Event: {'peername': ('192.168.100.10', 22968), 'sequence': '0006', 'receiver': '6666', 'line': '1234', 'account': '001234', 'qualifier': 'N', 'area': '01', 'event_code': 'YK001', 'sia_event': 'YK', 'sia_code': '001', 'text': 'HA', 'panel_id': 57005, 'system_account': '001234', 'timestamp': None, 'message_type': <MessageType.SIA: 1>, 'encrypted_ack': True, 'sia_type': 'Communications Restoral', 'sia_description': 'TRANSMITTER has resumed communication with a RECEIVER', 'sia_concerns': None}

# SIA
# Decrypted data: b'\n01010034"SIA-DCS"0009R6666L1234[#005412|Nri04/UA105]\r\x00\x00'
# Event: {'peername': ('192.168.100.10', 23009), 'sequence': '0009', 'receiver': '6666', 'line': '1234', 'account': '005412', 'qualifier': 'N', 'area': '04', 'event_code': 'UA105', 'sia_event': 'UA', 'sia_code': '105', 'text': None, 'panel_id': None, 'system_account': '005412', 'timestamp': None, 'message_type': <MessageType.SIA: 1>, 'encrypted_ack': True, 'sia_type': 'Untyped Zone Alarm', 'sia_description': 'Alarm condition from zone of unknown type', 'sia_concerns': 'Zone or point'}
# Decrypted data: b'\n01010034"SIA-DCS"0010R6666L1234[#005412|Nri04/UA105]\r\x00\x00'
# Event: {'peername': ('192.168.100.10', 23013), 'sequence': '0010', 'receiver': '6666', 'line': '1234', 'account': '005412', 'qualifier': 'N', 'area': '04', 'event_code': 'UA105', 'sia_event': 'UA', 'sia_code': '105', 'text': None, 'panel_id': None, 'system_account': '005412', 'timestamp': None, 'message_type': <MessageType.SIA: 1>, 'encrypted_ack': True, 'sia_type': 'Untyped Zone Alarm', 'sia_description': 'Alarm condition from zone of unknown type', 'sia_concerns': 'Zone or point'}

# ADM-CID
# Decrypted data: b'\n01010034"ADM-CID"0005RABCDLDEAD[#005412|1150 04 261]\r\x00\x00'
# Event: {'peername': ('192.168.100.10', 23118), 'sequence': '0005', 'receiver': 'ABCD', 'line': 'DEAD', 'account': '005412', 'qualifier': '1', 'event_code': '150', 'area': '04', 'zone': '261', 'panel_id': None, 'system_account': '005412', 'timestamp': None, 'message_type': <MessageType.CID: 2>, 'sia_event': 'UA', 'encrypted_ack': True, 'sia_type': 'Untyped Zone Alarm', 'sia_description': 'Alarm condition from zone of unknown type', 'sia_concerns': 'Zone or point'}
# Decrypted data: b'\n01010034"ADM-CID"0006RABCDLDEAD[#005412|1150 04 261]\r\x00\x00'
# Event: {'peername': ('192.168.100.10', 23122), 'sequence': '0006', 'receiver': 'ABCD', 'line': 'DEAD', 'account': '005412', 'qualifier': '1', 'event_code': '150', 'area': '04', 'zone': '261', 'panel_id': None, 'system_account': '005412', 'timestamp': None, 'message_type': <MessageType.CID: 2>, 'sia_event': 'UA', 'encrypted_ack': True, 'sia_type': 'Untyped Zone Alarm', 'sia_description': 'Alarm condition from zone of unknown type', 'sia_concerns': 'Zone or point'}

logging.basicConfig(level=logging.DEBUG)
_LOGGER = logging.getLogger(__name__)


def unscramble_key(key):
    key = bytearray(key)
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


async def async_send_message(config, msg, d, time_between):
    """Send message async."""
    host = config["host"]
    port = config["port"]
    _LOGGER.debug("Opening connection")

    reader, writer = await asyncio.open_connection(host, port)
    try:
        print("Reading scrambled key")
        scrambled_key = await reader.read(24)
        key = unscramble_key(scrambled_key)
        cipher = DES3.new(key, mode=DES3.MODE_ECB)

        if d.get("encrypted_panel_id") is not None:
            d["panel_id"] = codecs.encode(
                cipher.encrypt(("{:08X}".format(d["panel_id"])).encode()), "hex"
            ).upper()
            # panel_id = base64.b16decode(d["panel_id"])
            # panel_id = cipher.decrypt(panel_id).decode()
            # print(panel_id)

        print(d)

        msg = msg.format(**d)

        data = msg.encode()
        _LOGGER.debug("Writing [%s]", data)

        block_size = 8
        padding_len = block_size - len(data) % block_size
        padding = bytearray(chr(0) * (padding_len), "ascii")
        data += padding
        data = cipher.encrypt(data)
        writer.write(data)
        await writer.drain()

        reply = await reader.read(1024)
        reply = cipher.decrypt(reply)
        _LOGGER.debug("Got [%s] from server", reply)

        if reply[:2] == b"ID":
            params["panel_id"] = int(reply[2:10], 16)
            reply = await reader.read(1024)
            reply = cipher.decrypt(reply)
            _LOGGER.debug("Got [%s] from server", reply)

        assert reply == b"ACK\r\x00\x00\x00\x00"

        await asyncio.sleep(time_between)

    finally:
        writer.close()


if __name__ == "__main__":
    """Run main with a config."""
    _LOGGER.info(sys.argv)
    try:  # sys.argv.index(1)
        file = sys.argv[1]
    except:
        file = "tests//config.json"
    with open(file, "r") as f:
        config = json.load(f)

    asyncio.get_event_loop().run_until_complete(
        async_send_message(config, v1_hb, params, 1)
    )
    asyncio.get_event_loop().run_until_complete(
        async_send_message(config, v2_hb, params, 1)
    )
    for i in range(1, 20):
        asyncio.get_event_loop().run_until_complete(
            async_send_message(config, v2_hb, params, 2)
        )
        asyncio.get_event_loop().run_until_complete(
            async_send_message(
                config, xsia, params | {"sequence": i, "encrypted_panel_id": True}, 2
            )
        )
