"""Tests for OHEvent."""

from datetime import datetime

from osbornehoffman import OHEvent, MessageType


class TestOHEvent:
    """Tests for the OHEvent dataclass."""

    def test_code_returns_sia_event(self):
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.SIA,
            sia_event="BA",
        )
        assert event.code == "BA"

    def test_code_defaults_to_rp_for_heartbeat_v1(self):
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.HB_V1,
        )
        assert event.code == "RP"

    def test_code_defaults_to_rp_for_heartbeat_v2(self):
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.HB_V2,
        )
        assert event.code == "RP"

    def test_code_returns_none_when_no_sia_event(self):
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.DHR,
        )
        assert event.code is None

    def test_ri_returns_sia_zone(self):
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.SIA,
            sia_zone="003",
            area="01",
        )
        assert event.ri == "003"

    def test_ri_falls_back_to_area(self):
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.SIA,
            area="04",
        )
        assert event.ri == "04"

    def test_ri_falls_back_to_zone(self):
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.CID,
            zone="261",
        )
        assert event.ri == "261"

    def test_ri_defaults_to_zero(self):
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.HB_V1,
        )
        assert event.ri == "0"

    def test_effective_account_prefers_system_account(self):
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.SIA,
            system_account="001234",
            account="005412",
        )
        assert event.effective_account == "001234"

    def test_effective_account_falls_back_to_account(self):
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.SIA,
            account="005412",
        )
        assert event.effective_account == "005412"

    def test_to_dict(self):
        ts = datetime(2024, 3, 28, 12, 0, 0)
        event = OHEvent(
            peername=("127.0.0.1", 1234),
            message_type=MessageType.SIA,
            sia_event="BA",
            timestamp=ts,
        )
        d = event.to_dict()
        assert d["message_type"] == "SIA"
        assert d["timestamp"] == "2024-03-28T12:00:00"
        assert d["sia_event"] == "BA"
        assert "panel_iv" not in d

    def test_from_parsed(self):
        raw = {
            "peername": ("127.0.0.1", 5000),
            "message_type": MessageType.CID,
            "system_account": "001234",
            "account": "005412",
            "qualifier": "1",
            "event_code": "150",
            "area": "04",
            "zone": "261",
            "sia_event": "UA",
            "encrypted_ack": True,
        }
        event = OHEvent.from_parsed(raw)
        assert event.message_type == MessageType.CID
        assert event.system_account == "001234"
        assert event.account == "005412"
        assert event.sia_event == "UA"
        assert event.zone == "261"
        assert event.code == "UA"
        assert event.effective_account == "001234"
