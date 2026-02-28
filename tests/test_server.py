"""Tests for OHServer and OHConnection."""

import re

from osbornehoffman.server import (
    CID_MATCHER,
    HB_V1_MATCHER,
    HB_V2_MATCHER,
    SIA_MATCHER,
    V4_HEADER_MATCHER,
    MessageType,
)


class TestMessageRegexes:
    """Test that the protocol regex patterns match expected messages."""

    def test_hb_v1_match(self):
        msg = "SRDEADLBEEF    F0000DXX    \x00"
        m = HB_V1_MATCHER.match(msg)
        assert m is not None
        assert m.group("receiver") == "DEAD"
        assert m.group("line") == "BEEF"
        assert m.group("system_account") == "F0000D"

    def test_hb_v2_match(self):
        msg = "SRDEADLBEEF    F0000DXX    \x00[ID2F96C533]\x00"
        m = HB_V2_MATCHER.match(msg)
        assert m is not None
        assert m.group("receiver") == "DEAD"
        assert m.group("line") == "BEEF"
        assert m.group("system_account") == "F0000D"
        assert m.group("panel_id") == "2F96C533"

    def test_sia_match(self):
        msg = "\n01010053\"SIA-DCS\"0001R6666L1234[#001234|Nri01/NR001*'HA'NM]E69B557E0CE8BD98|#001234\r\x00"
        m = SIA_MATCHER.match(msg)
        assert m is not None
        assert m.group("sequence") == "0001"
        assert m.group("receiver") == "6666"
        assert m.group("line") == "1234"
        assert m.group("account") == "001234"
        assert m.group("qualifier") == "N"
        assert m.group("area") == "01"
        assert m.group("sia_event") == "NR"
        assert m.group("sia_zone") == "001"
        assert m.group("text") == "HA"
        assert m.group("system_account") == "001234"

    def test_cid_match(self):
        msg = "\n01010034\"ADM-CID\"0005RABCDLDEAD[#005412|1150 04 261]\r\x00"
        m = CID_MATCHER.match(msg)
        assert m is not None
        assert m.group("sequence") == "0005"
        assert m.group("receiver") == "ABCD"
        assert m.group("line") == "DEAD"
        assert m.group("account") == "005412"
        assert m.group("qualifier") == "1"
        assert m.group("event_code") == "150"
        assert m.group("area") == "04"
        assert m.group("zone") == "261"

    def test_v4_header_match(self):
        msg = "#40RDEADL1234AF0000DS0040"
        m = V4_HEADER_MATCHER.match(msg)
        assert m is not None
        assert m.group("receiver") == "DEAD"
        assert m.group("line") == "1234"
        assert m.group("system_account") == "F0000D"
        assert m.group("payload_length") == "0040"


class TestMessageType:
    """Test the MessageType enum."""

    def test_values(self):
        assert MessageType.SIA.value == 1
        assert MessageType.CID.value == 2
        assert MessageType.HB_V1.value == 3
        assert MessageType.HB_V2.value == 4
        assert MessageType.DHR.value == 5
        assert MessageType.V4.value == 6
