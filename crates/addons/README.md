# Local metadata add-ons

`raven-store` provides an SQLite database shared by GUI, headless, and MCP clients.
It does not read IDB/I64 files or implement the Hex-Rays Teams/Lumina protocols.

Annotations are keyed by binary identity and an unsigned 64-bit address stored as
fixed-width hexadecimal text. Each mutation runs in an immediate transaction,
increments its revision, and records the before/after values and author in an
append-only audit table. `expected_revision = Some(0)` means create only;
`Some(n)` means compare and update revision n; `None` is an explicit unconditional
update. Omitted names/comments retain their previous value; an empty string
explicitly clears their text.

Annotation export is JSON with schema version 1. Import requires a caller-provided
expected revision for every imported address. The entire import rolls back on a
conflict or malformed entry. Imported historical revisions never overwrite local
revision counters.

Function signatures use a domain-separated SHA-256 fingerprint of architecture
and exact function bytes. Metadata includes a name, optional prototype, and
comment. Changed relocation bytes, compiler output, or architecture produce a
different fingerprint; this is not fuzzy matching or relocation normalization.

SQLite WAL and a five-second busy timeout support separate local processes.
There is no network server, login system, seat pooling, or remote synchronization
in this crate.
