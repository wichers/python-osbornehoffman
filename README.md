# osbornehoffman

Python 3 package to interface with Osborne-Hoffman (OH+CID, OH+SIA or OH+XSIA) compatible panels:

  - CSX75 Panel Range (CS7050(N) TCP/IP gateway)
  - CSX75 Panel Range (CS9104/9204 Video Verification Module)
  - CSX75 Panel Range (CS7002(N) GSM/GPRS module)
  - ATS MASTER Panel range (ATS2xxx, ATS3xxx, ATS4xxx with ATS1806 or ATS1809)
  - ATS Advanced (with TDA74xx GRPS/IP modules or ATS7310 GSM/GPRS module)
  - ATS Advanced IP (ATSx000A-IP, ATSx500A-IP)
  - NetworX Panel Range (NX-590(N)E TCP/IP gateway)
  - NetworX Panel Range (NX-9104/9204 Video Verification Module)
  - NetworX Panel Range (NX-7002(N) GSM/GPRS module)
  - Simon Panel Range (60-938)

## Protocol Support

- **V1-V3**: 3DES/ECB encryption with XOR-scrambled key handshake
- **V4**: AES-256/CBC encryption with Diffie-Hellman key exchange and IV mixing

The Osborne-Hoffman protocol is a TCP overlay protocol where the server sends a scrambled 192-bit 3DES key to the panel. V4 extends this with a Diffie-Hellman negotiation for AES-256 key derivation.

## Installation

```
pip install osbornehoffman
```

Requires Python >= 3.10 and `pycryptodome`.

## Usage

### Using OHReceiver (recommended)

```python
import asyncio
from osbornehoffman import OHReceiver, OHAccount, OHEvent

async def main():
    async def on_event(event: OHEvent) -> None:
        print(f"Event: code={event.code}, account={event.effective_account}")

    accounts = [OHAccount("001234")]
    async with OHReceiver("0.0.0.0", 8996, accounts, on_event) as receiver:
        await asyncio.Event().wait()  # run forever

asyncio.run(main())
```

### Using OHServer directly

```python
import asyncio
from osbornehoffman import OHServer, OHAccount

async def main():
    async def process_event_cb(event: dict) -> bool:
        print("Processing event")
        return True

    accounts = {"001234": OHAccount("001234")}
    server = OHServer("0.0.0.0", 8996, accounts, process_event_cb)
    await server.start_server()
    async with server.server:
        await server.server.serve_forever()

asyncio.run(main())
```

## Key Classes

- `OHReceiver` - High-level async receiver with lifecycle management (start/stop, context manager)
- `OHServer` - Low-level TCP server handling protocol framing and encryption
- `OHAccount` - Account configuration (account_id, panel_id, forward_heartbeat)
- `OHEvent` - Parsed event dataclass with `code`, `ri`, `effective_account` properties
- `OHKeyStore` - JSON-based persistence for V4 AES keys
- `OHVideoServer` - TCP server for receiving video clips from panels
- `OHVideoEvent` - Parsed video clip event with image data and alarm info
- `MessageType` - Enum for event types (SIA, CID, HB_V1, HB_V2, DHR, V4)
