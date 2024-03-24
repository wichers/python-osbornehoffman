from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any

_LOGGER = logging.getLogger(__name__)


class InvalidAccountFormatError(Exception):
    """Error for when the account is not a hex string."""


class InvalidAccountLengthError(Exception):
    """Error for when the key is not the right amount of characters."""


@dataclass
class OsborneHoffmanAccount:
    """Class for Osborne Hoffman Accounts."""

    account_id: str
    panel_id: int

    def __post_init__(self) -> None:
        self.account_id = self.account_id.upper()

    @classmethod
    def validate_account(cls, account_id: str | None = None) -> None:
        """Validate a accounts information, either with one of the fields or both.

        Keyword Arguments:
            account_id {str} -- The account id specified by the alarm system,
                should be 3-16 characters hexadecimal. (default: {None})

        Raises:
            InvalidAccountFormatError: If the account id is not a valid hexadecimal string.
            InvalidAccountLengthError: If the account id does not have between 3 and 16 characters.

        """
        if account_id is not None:  # pragma: no cover
            try:
                int(account_id, 16)
            except ValueError as exc:
                raise InvalidAccountFormatError from exc
            try:
                assert 3 <= len(account_id) <= 16
            except AssertionError as exc:
                raise InvalidAccountLengthError from exc

    def to_dict(self) -> dict[str, Any]:
        """Create a dict from the dataclass."""
        return asdict(self)

    @classmethod
    def from_dict(cls, acc: dict[str, Any]) -> OsborneHoffmanAccount:
        """Create a OH Account from a dict."""
        return cls(**acc)
