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

    accounts = {"001234": OHAccount("001234", 0)}
    ctx = OHServer(HOST, PORT, accounts, process_event_cb)
    await ctx.start_server()
    async with ctx.server:
        await ctx.server.serve_forever()


asyncio.run(main())
