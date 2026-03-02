"""Test server: run the OH receiver and log all events from connected panels.

Starts the OHReceiver TCP server and logs every event (heartbeats, SIA, CID, V4)
to the console. Optionally starts the video server on a separate port.
Connect your own panel or test client to it.

Usage:
    python tests/test.py
    python tests/test.py --host 0.0.0.0 --port 8996 --account 001234
    python tests/test.py --host 0.0.0.0 --port 8996 --video-port 9995

Default: listens on 127.0.0.1:8996, account 001234.
"""

import argparse
import asyncio
import json
import logging

from osbornehoffman import OHReceiver, OHAccount, OHEvent, OHVideoEvent

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
_LOGGER = logging.getLogger("test_server")


async def main():
    parser = argparse.ArgumentParser(description="OH test server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8996)
    parser.add_argument("--account", default="001234")
    parser.add_argument("--panel-id", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--video-port", type=int, default=None)
    parser.add_argument("--keystore", default=None, help="Path to keystore JSON for V4 AES keys")
    args = parser.parse_args()

    event_count = 0
    video_count = 0

    async def on_event(event: OHEvent) -> None:
        """Log every received supervision event."""
        nonlocal event_count
        event_count += 1
        _LOGGER.info(
            "EVENT #%d  type=%-6s  code=%-4s  account=%-6s  zone=%-4s",
            event_count,
            event.message_type.name,
            event.code or "-",
            event.effective_account or "-",
            event.ri or "-",
        )
        if event.sia_description:
            _LOGGER.info("  sia: %s — %s", event.sia_type, event.sia_description)
        if event.text:
            _LOGGER.info("  text: %s", event.text)
        _LOGGER.info("  full: %s", json.dumps(event.to_dict(), default=str))

    async def on_video(event: OHVideoEvent) -> None:
        """Log every received video clip event."""
        nonlocal video_count
        video_count += 1
        _LOGGER.info(
            "VIDEO #%d  clip_id=%d  camera=%d  zone=%d  images=%d  "
            "size=%d bytes  type=%s",
            video_count,
            event.clip_id,
            event.camera_number,
            event.zone_number,
            event.total_images,
            event.image_size,
            event.file_extension,
        )
        if event.sia_event:
            _LOGGER.info(
                "  alarm: %s — %s", event.sia_event, event.sia_description or "-"
            )
        _LOGGER.info("  alarm_message: %s", event.alarm_message)

    accounts = [
        OHAccount(args.account, panel_id=args.panel_id, forward_heartbeat=True)
    ]
    receiver = OHReceiver(
        args.host,
        args.port,
        accounts,
        on_event,
        keystore_path=args.keystore,
        video_port=args.video_port,
        video_function=on_video if args.video_port else None,
    )

    _LOGGER.info("Starting OH receiver on %s:%d (account=%s)", args.host, args.port, args.account)
    if args.video_port:
        _LOGGER.info("Starting video server on %s:%d", args.host, args.video_port)
    await receiver.async_start()
    _LOGGER.info("OH receiver ready — waiting for connections (Ctrl+C to stop)")

    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        _LOGGER.info(
            "Shutting down (%d events, %d video clips received)",
            event_count,
            video_count,
        )
        await receiver.async_stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
