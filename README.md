# osbornehoffman

Python 3 package to interface with Osborne-Hoffman (OH+CID, OH+SIA or OH+XSIA) compatible panels (up to OH version 3.0):

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

The Osborne-Hoffman protocol is a simple TCP overlay protocol that adds Triple DES support, this starts with the server sending a scrambled 192-bit DES key to the client. After the key is sent client communication can start whereby each packet is padded with zero's (not your standard padding scheme) and encrypted with 3DES ECB.

## Installation

pip3 install osbornehoffman

## Usage

```python
import asyncio
import logging

from osbornehoffman import OHServer, OHAccount

logging.basicConfig(level=logging.DEBUG)


async def main():

    async def process_event_cb(event: dict) -> bool:
        """Process callback from server."""
        print("Processing event")
        return True

    HOST, PORT = "0.0.0.0", 12000

    accounts = {"001234": OHAccount("001234", 100)}
    ctx = OHServer(HOST, PORT, accounts, process_event_cb)
    await ctx.start_server()
    async with ctx.server:
        await ctx.server.serve_forever()

asyncio.run(main())
```
