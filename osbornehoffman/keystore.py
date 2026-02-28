"""Per-panel AES key persistence for OH V4 protocol."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)


class OHKeyStore:
    """Stores and retrieves per-panel AES keys for V4 protocol.

    Keys are persisted as a JSON file mapping account IDs to hex-encoded
    AES keys.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        """Initialize the keystore.

        Args:
            path: Path to the JSON keystore file. If None, keys are
                  stored in memory only (not persisted).
        """
        self._path = Path(path) if path else None
        self._keys: dict[str, str] = {}
        if self._path and self._path.exists():
            self._load()

    def _load(self) -> None:
        """Load keys from disk."""
        try:
            with open(self._path, "r") as f:
                data = json.load(f)
            self._keys = data.get("keys", {})
            _LOGGER.debug("Loaded %d keys from keystore", len(self._keys))
        except (json.JSONDecodeError, OSError) as exc:
            _LOGGER.warning("Failed to load keystore: %s", exc)
            self._keys = {}

    def _save(self) -> None:
        """Save keys to disk."""
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w") as f:
                json.dump({"keys": self._keys}, f, indent=2)
        except OSError as exc:
            _LOGGER.warning("Failed to save keystore: %s", exc)

    def get_aes_key(self, account: str) -> bytes | None:
        """Get the AES key for an account.

        Returns the 32-byte AES key or None if not found.
        """
        hex_key = self._keys.get(account.upper())
        if hex_key is None:
            return None
        return bytes.fromhex(hex_key)

    def store_aes_key(self, account: str, key: bytes) -> None:
        """Store an AES key for an account.

        Args:
            account: Account ID (will be uppercased).
            key: 32-byte AES-256 key.
        """
        self._keys[account.upper()] = key.hex().upper()
        self._save()
        _LOGGER.debug("Stored AES key for account %s", account.upper())

    def remove_key(self, account: str) -> None:
        """Remove the AES key for an account."""
        self._keys.pop(account.upper(), None)
        self._save()

    @staticmethod
    def derive_pin(aes_key: bytes) -> str:
        """Derive a PIN from an AES key using PBKDF2.

        Matches Java implementation: PBKDF2WithHmacSHA512, iterations=5000,
        salt=16 zero bytes, key_length=4 bytes (32 bits).

        Returns the PIN formatted as "XX XX XX XX".
        """
        salt = b"\x00" * 16
        dk = hashlib.pbkdf2_hmac("sha512", aes_key, salt, 5000, dklen=4)
        return " ".join(f"{b:02X}" for b in dk)
