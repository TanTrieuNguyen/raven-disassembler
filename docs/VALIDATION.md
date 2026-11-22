# Validation

Original Rivet RE verification before the rename. Raw local captures and build logs are kept outside Git.

Verification date: 2026-11-22. Host: macOS x86_64. Rust toolchain: 1.100.0, installed locally under `.tools` without shell-profile changes.

The public IDA application and proprietary add-ons were not executed or compared. No full-parity claim is made.

## Evidence already collected

- Core unit coverage: generated ELF x64 direct calls/conditional CFG, Mach-O ARM64, COFF x86, ARM and Thumb, malformed input and mapping bounds, entropy, unresolved indirect targets. Additional regressions cover Mach-O entry file offset conversion, header seed exclusion and skipped-data CFG boundaries.
- Store unit coverage: reopen persistence, revision CAS, two-connection conflicts, audit history, atomic JSON merge, architecture isolation for exact-byte fingerprints, full u64 addresses.
- Fixture: `fixtures/sample.c`, built with host `cc -O0 -g`, output `fixtures/sample`. `nm` and `otool` are independent checks of symbols, addresses and branch instructions.
- REA evidence: `rea-fixture-evidence.json`, evidence ID `ev_75df80290f9335f3deab709c4626299650c7234d5616196b8fd4528e32ecde24`. Independently parsed fixture as Mach-O x86_64 with SHA-256 `f72972a80e4b9510406cde8e579ec914dd101cbac683d77330aae63f8240c356`. This validates artifact identity/format, not Rivet disassembly equivalence or IDA behavior. Static hardening declarations do not establish exploitability or runtime enforcement.

## Results so far

- `cargo test --workspace`: **19 passed, 0 failed** (10 core + 4 store + 4 workflow + 1 protocol).
- `cargo fmt --all --check`: passed.
- `cargo clippy --workspace --all-targets --features gui -- -D warnings`: passed.
- Debug build smoke: CLI analysis, disassembly/CFG, persisted annotations, exact signatures, IOC candidates, mixed-success batch, JSON report, process plugin, HTTP Assist mock and MCP subprocess all passed.
- Independent `nm`/`otool` comparison: fixture entry `0x100003f30`, `_transform` at `0x100003f00` (43 bytes), `_main` at `0x100003f30` (48 bytes); matching direct calls/branches/imports/exports.

## Release checks

- `cargo build --release --features gui --bins`: passed, optimized x86_64 Mach-O GUI, CLI and MCP executables.
- `python3 scripts/smoke.py --profile release`: passed. See `release-smoke.json`.
- `file` / `otool -L`: macOS x86_64, links only system libraries/frameworks; Capstone and SQLite are bundled statically through crate builds.
- GUI binary load-command minimum is macOS 10.12; the app plist requires 10.15. Only the current host was tested; this declaration is not testing of older macOS releases.
- GUI release launched, loaded `fixtures/sample`, displayed `_transform` with 43 bytes, 14 instructions and 4 blocks. Target window screenshot captured and visually inspected: `gui-preview.png`; process/window identity recorded in `gui-launch.json`. This establishes initial render/load only, not all UI interactions.
- Build/test/Clippy transcripts: `release-build.log`, `rust-tests.log`, `clippy.log`.


A configured real model, MCP host application interoperability, remote collaboration, Windows/Linux/macOS arm64 and complete GUI interaction/accessibility coverage remain unverified. Mock-model checks establish request/response plumbing only.

Packaging: macOS `.app` uses an ad-hoc developer signature (not notarized). The package script signs and verifies the app and the archive is checked for ZIP readback integrity.
