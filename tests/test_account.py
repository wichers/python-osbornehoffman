"""Tests for OHAccount."""

import pytest

from osbornehoffman import (
    InvalidAccountFormatError,
    InvalidAccountLengthError,
    InvalidPanelIDFormatError,
    InvalidPanelIDLengthError,
    OHAccount,
)


class TestOHAccount:
    """Tests for the OHAccount dataclass."""

    def test_default_values(self):
        acc = OHAccount("001234")
        assert acc.account_id == "001234"
        assert acc.panel_id == 0
        assert acc.forward_heartbeat is True

    def test_account_id_uppercased(self):
        acc = OHAccount("abcdef")
        assert acc.account_id == "ABCDEF"

    def test_panel_id_preserved(self):
        acc = OHAccount("001234", panel_id=42)
        assert acc.panel_id == 42

    def test_forward_heartbeat_preserved(self):
        acc = OHAccount("001234", forward_heartbeat=False)
        assert acc.forward_heartbeat is False

    def test_to_dict(self):
        acc = OHAccount("001234", panel_id=10, forward_heartbeat=False)
        d = acc.to_dict()
        assert d == {
            "account_id": "001234",
            "panel_id": 10,
            "forward_heartbeat": False,
        }

    def test_from_dict(self):
        d = {"account_id": "ABCDEF", "panel_id": 5, "forward_heartbeat": True}
        acc = OHAccount.from_dict(d)
        assert acc.account_id == "ABCDEF"
        assert acc.panel_id == 5
        assert acc.forward_heartbeat is True


class TestValidateAccount:
    """Tests for OHAccount.validate_account()."""

    def test_valid_account(self):
        OHAccount.validate_account(account_id="001234")

    def test_valid_account_and_panel_id(self):
        OHAccount.validate_account(account_id="ABCDEF", panel_id="1A2B")

    def test_invalid_account_format(self):
        with pytest.raises(InvalidAccountFormatError):
            OHAccount.validate_account(account_id="GGGGGG")

    def test_invalid_account_length_too_short(self):
        with pytest.raises(InvalidAccountLengthError):
            OHAccount.validate_account(account_id="AB")

    def test_invalid_account_length_too_long(self):
        with pytest.raises(InvalidAccountLengthError):
            OHAccount.validate_account(account_id="A" * 17)

    def test_invalid_panel_id_format(self):
        with pytest.raises(InvalidPanelIDFormatError):
            OHAccount.validate_account(panel_id="ZZZZ")

    def test_invalid_panel_id_length_too_long(self):
        with pytest.raises(InvalidPanelIDLengthError):
            OHAccount.validate_account(panel_id="A" * 17)

    def test_none_account_skips_validation(self):
        OHAccount.validate_account(account_id=None, panel_id=None)
