"""High-level async receiver for Osborne Hoffman alarm panels.

Runs a TCP server that panels connect to, converting raw protocol events
into OHEvent objects. Provides async_start(), async_stop(), context manager
support, and an accounts property.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import TracebackType
from typing import Any, Type

from .account import OHAccount
from .event import OHEvent
from .keystore import OHKeyStore
from .server import OHServer
from .video import OHVideoEvent, OHVideoServer

_LOGGER = logging.getLogger(__name__)


class OHReceiver:
    """Async client (TCP server) for Osborne Hoffman alarm panels.

    Runs a TCP server that alarm panels connect to, acting as an alarm
    receiver (similar to the Java OHNetRec). Converts raw protocol messages
    into OHEvent objects and dispatches them via an async callback.
    """

    def __init__(
        self,
        host: str,
        port: int,
        accounts: list[OHAccount],
        function: Callable[[OHEvent], Awaitable[None]],
        keystore_path: str | Path | None = None,
        video_port: int | None = None,
        video_function: Callable[[OHVideoEvent], Awaitable[None]] | None = None,
    ) -> None:
        """Initialize the OH receiver.

        Args:
            host: Host to listen on (e.g., "" or "0.0.0.0").
            port: TCP port to listen on.
            accounts: List of OH accounts to accept.
            function: Async callback called for each valid event.
            keystore_path: Path for V4 AES key persistence (optional).
            video_port: TCP port for video server (default: None = disabled).
            video_function: Async callback for video clip events (optional).
        """
        self._host = host
        self._port = port
        self._accounts_list = accounts
        self._accounts: dict[str, OHAccount] = {
            a.account_id: a for a in accounts
        }
        self._func = function
        self._keystore_path = keystore_path
        self._keystore: OHKeyStore | None = None
        self._server: OHServer | None = None
        self._video_port = video_port
        self._video_func = video_function
        self._video_server: OHVideoServer | None = None

    @property
    def accounts(self) -> list[OHAccount]:
        """Return the list of accounts."""
        return self._accounts_list

    @accounts.setter
    def accounts(self, accounts: list[OHAccount]) -> None:
        """Update the accounts list."""
        self._accounts_list = accounts
        self._accounts = {a.account_id: a for a in accounts}
        if self._server:
            self._server.accounts = self._accounts

    async def _event_callback(self, raw_event: dict) -> bool:
        """Convert raw event dict to OHEvent and invoke user callback."""
        oh_event = OHEvent.from_parsed(raw_event)
        try:
            await self._func(oh_event)
        except Exception:
            _LOGGER.exception("Error in event callback")
        return True

    async def async_start(self, **kwargs: Any) -> None:
        """Start the OH TCP server."""
        _LOGGER.debug("Starting OH receiver on %s:%d", self._host, self._port)

        if self._keystore_path:
            self._keystore = OHKeyStore(self._keystore_path)

        self._server = OHServer(
            host=self._host,
            port=self._port,
            accounts=self._accounts,
            callback=self._event_callback,
            keystore=self._keystore,
        )
        await self._server.start_server(**kwargs)

        if self._video_port is not None and self._video_func is not None:
            self._video_server = OHVideoServer(
                host=self._host,
                port=self._video_port,
                accounts=self._accounts,
                callback=self._video_func,
                keystore=self._keystore,
            )
            await self._video_server.start()

    async def async_stop(self) -> None:
        """Stop the OH TCP server."""
        _LOGGER.debug("Stopping OH receiver")
        if self._video_server:
            await self._video_server.stop()
            self._video_server = None
        if self._server:
            await self._server.close_server()
            self._server = None

    async def __aenter__(self) -> OHReceiver:
        """Start as async context manager."""
        await self.async_start()
        return self

    async def __aexit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_val: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Stop as async context manager."""
        await self.async_stop()
        return None
