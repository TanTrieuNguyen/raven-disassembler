# RAVEN Disassembler 0.1 — coverage against the requested Hex-Rays product family

RAVEN is an independent implementation. It is not IDA Pro, does not contain Hex-Rays code, and does not read IDB/I64 databases. This release does **not** satisfy full IDA Pro feature parity. The supplied image is a website product menu, not an application UI or a behavioral specification.

Source review date: 2026-11-22. Public documentation was inspected; no IDA executable, database, account, add-on package, or IDA runtime session was supplied or reverse engineered.

| Requested item | Working implementation in this release | Remaining work / exact boundary |
|---|---|---|
| IDA Pro GUI | Native Rust/egui workbench, functions, assembly, interactive CFG, synchronized Hex bytes and code-reference inspector, sections, imports/exports, strings, comments/renames, tool console | Independent UI. Optional Ghidra pseudocode. No native decompiler, debugger, full type system, patch assembler, signature normalization, IDB compatibility or broad processor parity |
| IDA Pro Headless | Rust library plus CLI inventory, disassembly, per-function analysis, JSON reports, batch with per-file errors | Same core as GUI; capped static scan, no full-program decompilation. Batch is sequential |
| IDA MCP | 25 tools, stdio JSON-RPC, initialize/ping/list/call, shared SQLite annotations | Independent tool names/schema. No compatibility promise with official IDA MCP or existing IDA plugins. No Streamable HTTP or fleet multiplexing |
| IDA Home / Free | Same independent engine without artificial license tiers | No Hex-Rays product/license integration |
| Malware Analysis | Static entropy, ASCII strings, IOC candidates, API-name markers | No automatic unpacker, emulator, sandbox connector, deobfuscator or verdict engine |
| Assist | Explicit CLI/MCP invocation of configurable chat-completions endpoint using bounded static context; no key required for local endpoints | No built-in model; no autonomous tool loop, solver, emulation, or device/runtime reasoning; real provider not tested |
| Teams | SQLite WAL shared metadata, authors, revision CAS, audit log, transactional JSON export/import | Local database/exchange only. No authenticated remote service, Git-aware three-way merge, IDB merge or distributed database replication |
| Private Lumina | SQLite private knowledge store with architecture + exact-byte SHA-256 signatures and name/prototype/comment metadata | Local only; exact bytes, not relocation-normalized function recognition. No Lumina protocol/server, FLIRT or fuzzy matching |
| hcli | `raven` CLI, analyze/batch/disasm/function/strings/triage/annotate/call/assist; feature/version information | No license manager or Hex-Rays installer; RAVEN uses Cargo and has no license server |
| SDK | Public Rust core/store APIs and JSON process-plugin SDK with executable/args manifest; sample plugin | No IDA C++ ABI/IDAPython compatibility; processor and loader plugins not implemented |
| GitHub Projects | Source workspace, tests, examples, lockfile, documentation | Official repositories are references, not products that can be cloned by adding a UI tab; no vendored Hex-Rays repositories |
| Plugins | Caller-selected executable plugins receive actual analysis JSON and return JSON | Not IDA plugin ABI. No package registry/update manager or sandbox; plugin deadline bounds direct process only |
| Training courses | Build/use/API instructions and sample C target | No reproduction of proprietary training content |

## Formats and analysis boundaries

- Inventory: thin ELF, PE/COFF and Mach-O through the `object` crate, and raw images with explicit CPU mode, endianness and base. Universal Mach-O must be thinned externally. Archives, firmware containers, .NET and DWARF types are not reconstructed.
- Disassembly: x86-32, x86-64, ARM, Thumb (odd address selects Thumb) and AArch64 through Capstone's C engine behind Rust bindings. The implementation is Rust, but third-party C code remains in Capstone and SQLite; it is not a pure-Rust-from-scratch replacement.
- ASCII strings: minimum four bytes, bounded collection. Not UTF-16/string decryption.
- Automatic direct-control-flow scan: first 2 MiB of executable section bytes in aggregate; linear sweep can interpret data as code. Symbol, entry and direct-call seeds are candidates. Stripped code, indirect calls, exception control flow and data xrefs remain incomplete/unknown.
- Function extents: symbol sizes where available; otherwise inferred to next seed/section boundary, capped at 4096 bytes. Function instruction output capped at 65536 bytes. No claim of recovered source.
- Memory reading: file-backed virtual addresses only. Reads stop at the section boundary; inspect actual returned length. No process memory or live addresses.
- Database identity: original file SHA-256. Annotations do not mutate the binary. GUI and MCP see the same metadata only when configured with the same SQLite path. Reload a selection before editing changes made elsewhere.

## Source references

- Product menu / requested family: https://hex-rays.com/
- IDA engine, GUI, debugger and decompiler scope: https://hex-rays.com/ida-pro
- Headless: https://hex-rays.com/ida-pro-headless
- MCP: https://docs.hex-rays.com/add-ons/mcp.md
- Malware: https://hex-rays.com/malware
- Assist: https://hex-rays.com/assist
- Teams: https://hex-rays.com/teams
- Lumina: https://hex-rays.com/lumina
- hcli: https://hcli.docs.hex-rays.com/
- SDK / official projects: https://github.com/HexRaysSA
- Community plugins: https://plugins.hex-rays.com/
- MCP stdio transport: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

These references establish public product descriptions, not implementation details or equivalence. The homepage and Teams page describe Teams differently (administration vs Git collaboration); RAVEN claims neither full implementation.
