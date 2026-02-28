"""Manual integration test: run the OH server and wait for panel connections."""

import asyncio
import logging

from osbornehoffman import OHClient, OHAccount, OHEvent

logging.basicConfig(level=logging.DEBUG)


async def main():

    async def on_event(event: OHEvent) -> None:
        """Process callback from server."""
        print(f"Event: code={event.code}, account={event.effective_account}")
        print(f"  type={event.message_type}, zone={event.ri}")
        print(f"  full={event.to_dict()}")

    HOST, PORT = "0.0.0.0", 8996

    accounts = [OHAccount("001234")]
    client = OHClient(HOST, PORT, accounts, on_event)
    await client.async_start()
    try:
        await asyncio.Event().wait()
    finally:
        await client.async_stop()


asyncio.run(main())
