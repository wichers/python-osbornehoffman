Release History
===============

2.1.0 (01-March-2026)
-------------------

Bug fixes and robustness improvements:

- fixed V4 CRC extraction using raw bytes instead of ASCII-decoded string (binary IV/payload bytes were dropped by errors="ignore", shifting CRC field offset)
- fixed V4 AES encryption using mixed IV (even bytes from server, odd from panel) matching Java MsgWorker behavior
- fixed V4 system_account always using authoritative V4 header value instead of inner payload fallback
- fixed panel ID assignment restricted to V2+ heartbeats only (V1 has no panel_id field)
- fixed panel ID decryption error handling (graceful fallback instead of crash)
- fixed DHR handling to use last known account (DHR messages have no system_account)
- fixed CID regex to make panel_id and system_account independently optional (matching SIA regex)
- added V4 NACK response for unprocessable V4 messages (matches Java NetRec behavior)
- added robust account resolution with session state and single-account fallback
- added per-connection mixed IV storage for V4 response encryption
- added dual-mode integration test suite (local OHServer + external Java NetRec)

2.0.0 (28-February-2026)
-------------------

Breaking changes and new features:

- added V4 protocol support (AES-256/CBC with Diffie-Hellman key exchange)
- added OHClient high-level async client with lifecycle management
- added OHEvent dataclass replacing raw dict event output
- added OHKeyStore for per-panel AES key persistence
- added OHDiffieHellman for V4 key negotiation (RFC 3526 Group 14)
- added PEP-561 py.typed marker
- fixed shared connection bug where all TCP connections used the same 3DES cipher
- fixed panel_id type error (calling .upper() on int)
- fixed forward_heartbeat always being overridden to False
- fixed uninitialized account variable when accounts dict is empty
- fixed per-connection cipher isolation (new 3DES key per TCP connection)
- changed minimum Python version to 3.10
- removed Python 3.8 compatibility code

1.0.3 (28-March-2024)

fixed issue where panel_id was not sent
panel id should only be changed in response to a heartbeat
added panel id validation
added option for skipping the forwarding of heartbeats

1.0.2 (24-March-2024)
-------------------

fixed issue where SIA events were not enriched

1.0.1 (24-March-2024)
-------------------

added pycryptodome dependency

1.0.0 (24-March-2024)
-------------------

Initial revision.