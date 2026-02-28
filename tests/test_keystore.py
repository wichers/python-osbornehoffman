"""Tests for OHKeyStore."""

import json
import os
import tempfile

import pytest

from osbornehoffman import OHKeyStore


class TestOHKeyStore:
    """Tests for key persistence."""

    def test_store_and_retrieve_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            ks = OHKeyStore(path)
            key = os.urandom(32)
            ks.store_aes_key("001234", key)
            retrieved = ks.get_aes_key("001234")
            assert retrieved == key
        finally:
            os.unlink(path)

    def test_get_missing_key_returns_none(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            ks = OHKeyStore(path)
            assert ks.get_aes_key("nonexistent") is None
        finally:
            os.unlink(path)

    def test_persistence_across_instances(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            key = os.urandom(32)
            ks1 = OHKeyStore(path)
            ks1.store_aes_key("ABCDEF", key)

            ks2 = OHKeyStore(path)
            assert ks2.get_aes_key("ABCDEF") == key
        finally:
            os.unlink(path)

    def test_derive_pin(self):
        key = os.urandom(32)
        pin = OHKeyStore.derive_pin(key)
        assert isinstance(pin, str)
        assert len(pin) > 0
        # Same input should produce same PIN
        assert OHKeyStore.derive_pin(key) == pin
        # Different input should produce different PIN
        other_key = os.urandom(32)
        assert OHKeyStore.derive_pin(other_key) != pin
