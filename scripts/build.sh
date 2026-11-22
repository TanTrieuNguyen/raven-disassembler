#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ -x .tools/cargo/bin/cargo ]; then . scripts/env.sh; fi
cargo fmt --all --check
cargo test --workspace
cargo build --release --features gui --bins
