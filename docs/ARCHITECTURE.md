# Architecture

`raven-core` owns an immutable binary byte snapshot, parsed file layout, symbols, strings and a bounded direct-control-flow reference inventory. It uses `object` for file parsing and Capstone for instruction decoding. It never executes the input. Loader addresses remain distinct from file offsets; unbacked memory is not invented.

`raven-store` owns a SQLite connection with WAL, annotations keyed by original SHA-256 plus lossless u64 address, append-only revision events and architecture-bound exact-byte signatures. Revision checks and writes occur under an immediate transaction. JSON import is all-or-nothing and demands explicit expected revisions.

`raven` provides a shared Workspace API, CLI and MCP frontend. Each process owns its active binary snapshot. GUI and MCP may have independent active binary sessions while sharing SQLite metadata. `open_binary` constructs the new analysis before replacing the current one, so a parse error preserves the previous session. A report contains analysis metadata and annotations; it does not embed the source executable and is not a reloadable disassembler database.

`raven-gui` is native Rust/egui. File loading occurs on a worker. Function selection decodes cached bytes. The block view displays real basic blocks and successor addresses as cards, not a spatial graph editor. The GUI explicitly lists missing engine capabilities. Metadata edits use the selected revision and report conflicts.

`raven-mcp` uses newline-delimited JSON-RPC on stdio. It supports lifecycle negotiation, tool discovery, tool calls and operational-error content. Unsupported tool/method calls are protocol errors. No unadvertised resources, prompts, HTTP transport or execution engine is implied. Logging is not mixed into protocol stdout.

Plugins are separate user-selected executables. The manifest chooses an absolute executable plus literal argument vector; no shell expansion occurs. Analysis is sent on stdin as one JSON object. stdout must be JSON and stderr is drained separately. Direct-child timeout and output bounds are enforced; process-tree ownership/isolation is not provided.

Assist is an optional explicit network operation. Endpoint/model/key live in environment variables. The bounded static context is sent with the user's question, and responses stay separate from deterministic facts and persisted annotations. No provider secrets are printed. It is an explanation adapter, not the full autonomous Assist product.

## Implementation order toward larger parity

1. Format coverage: fat Mach-O selection, raw loader/base-address configuration, relocation tables, PE exception/unwind and Mach-O function-start metadata.
2. Analysis correctness: recursive traversal, typed instruction semantics, data/indirect references, jump tables, unwind-based function bounds, normalized signatures, architecture test corpus.
3. Intermediate representation: instruction lifting, SSA, control-flow structuring, calling conventions, type propagation, then a real bounded decompiler with equivalence tests.
4. Debugging: debugger adapter protocol, explicit launch/attach sessions, stop state, memory/register views and static/runtime address translation.
5. Remote metadata: authenticated service, per-project roles, transport, three-way metadata merge, Git exchange and conflict UI. Local SQLite WAL is not remote replication.
6. Malware tools: signature-rule import, bounded emulator and unpacking workflows, sandbox evidence binding; keep observed behavior distinct from string heuristics.
7. SDK: stable processor/loader traits, plugin package verification/update manager and documented compatibility versioning.
8. Product hardening: cancellation and budgets across parser/native decoding, file-dialog UX, virtualized data views, UI accessibility verification, macOS arm64/Linux/Windows packaging and interoperability tests with real MCP clients.

Each stage needs executable fixtures and behavior checks. Public marketing text alone cannot establish fidelity to proprietary algorithms or guarantee feature completeness.
