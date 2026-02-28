"""High-level async client for Osborne Hoffman alarm panels.

Provides a lifecycle API compatible with pysiaalarm's SIAClient pattern:
async_start(), async_stop(), context manager support, accounts property.
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

_LOGGER = logging.getLogger(__name__)


class OHClient:
    """Async client (TCP server) for Osborne Hoffman alarm panels.

    Despite the name "client", this runs a TCP server that panels connect to.
    The naming follows the pysiaalarm convention where the Home Assistant side
    is the "client" consuming alarm events.
    """

    def __init__(
        self,
        host: str,
        port: int,
        accounts: list[OHAccount],
        function: Callable[[OHEvent], Awaitable[None]],
        keystore_path: str | Path | None = None,
    ) -> None:
        """Initialize the OH client.

        Args:
            host: Host to listen on (e.g., "" or "0.0.0.0").
            port: TCP port to listen on.
            accounts: List of OH accounts to accept.
            function: Async callback called for each valid event.
            keystore_path: Path for V4 AES key persistence (optional).
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
        _LOGGER.debug("Starting OH client on %s:%d", self._host, self._port)

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

    async def async_stop(self) -> None:
        """Stop the OH TCP server."""
        _LOGGER.debug("Stopping OH client")
        if self._server:
            await self._server.close_server()
            self._server = None

    async def __aenter__(self) -> OHClient:
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
