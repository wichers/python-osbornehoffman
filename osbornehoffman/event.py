"""OHEvent dataclass for Osborne Hoffman protocol events."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from .server import MessageType


@dataclass
class OHEvent:
    """Represents a parsed Osborne Hoffman protocol event."""

    peername: tuple
    message_type: MessageType

    # Account identifiers
    system_account: str | None = None
    account: str | None = None

    # Connection identifiers
    receiver: str | None = None
    line: str | None = None
    sequence: str | None = None

    # Event details
    qualifier: str | None = None
    area: str | None = None
    event_code: str | None = None

    # SIA event info (2-char code like BA, PA, RP, etc.)
    sia_event: str | None = None
    sia_zone: str | None = None

    # CID-specific
    zone: str | None = None

    # Event text/description from panel
    text: str | None = None

    # Panel identification
    panel_id: int | None = None

    # Timing
    timestamp: datetime | str | None = None

    # Protocol details
    encrypted_ack: bool = False

    # V4 protocol fields
    payload_length: int | None = None
    panel_iv: bytes | None = field(default=None, repr=False)
    crc: int | None = None
    is_v4: bool = False

    # SIA code metadata (looked up from tables.py)
    sia_type: str | None = None
    sia_description: str | None = None
    sia_concerns: str | None = None

    @property
    def code(self) -> str | None:
        """Return the SIA event code, defaulting to 'RP' for heartbeats."""
        if self.sia_event:
            return self.sia_event
        if self.message_type in (MessageType.HB_V1, MessageType.HB_V2):
            return "RP"
        return None

    @property
    def ri(self) -> str | None:
        """Return the zone/receiver index for HA entity routing."""
        return self.sia_zone or self.area or self.zone or "0"

    @property
    def effective_account(self) -> str | None:
        """Return the effective account ID (system_account preferred)."""
        return self.system_account or self.account

    def to_dict(self) -> dict[str, Any]:
        """Convert to a dictionary."""
        d = asdict(self)
        if isinstance(d.get("timestamp"), datetime):
            d["timestamp"] = d["timestamp"].isoformat()
        if isinstance(d.get("message_type"), MessageType):
            d["message_type"] = d["message_type"].name
        # Remove bytes field for serialization
        d.pop("panel_iv", None)
        return d

    @classmethod
    def from_dict(cls, event: dict) -> dict:
        """Create from a raw parsed event dict (legacy compatibility)."""
        return event

    @classmethod
    def from_parsed(cls, raw: dict) -> OHEvent:
        """Create an OHEvent from a raw parsed event dict.

        This converts the dict output from OHConnection.parse_event()
        into a proper OHEvent dataclass instance.
        """
        return cls(
            peername=raw.get("peername", ("unknown", 0)),
            message_type=raw.get("message_type", MessageType.HB_V1),
            system_account=raw.get("system_account"),
            account=raw.get("account"),
            receiver=raw.get("receiver"),
            line=raw.get("line"),
            sequence=raw.get("sequence"),
            qualifier=raw.get("qualifier"),
            area=raw.get("area"),
            event_code=raw.get("event_code"),
            sia_event=raw.get("sia_event"),
            sia_zone=raw.get("sia_zone"),
            zone=raw.get("zone"),
            text=raw.get("text"),
            panel_id=raw.get("panel_id"),
            timestamp=raw.get("timestamp"),
            encrypted_ack=raw.get("encrypted_ack", False),
            payload_length=raw.get("payload_length"),
            panel_iv=raw.get("panel_iv"),
            crc=raw.get("crc"),
            is_v4=raw.get("is_v4", False),
            sia_type=raw.get("sia_type"),
            sia_description=raw.get("sia_description"),
            sia_concerns=raw.get("sia_concerns"),
        )
