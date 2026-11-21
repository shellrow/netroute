#!/usr/bin/env bash
set -euo pipefail

# cross can build FreeBSD binaries but has no FreeBSD test runner.
cross build --all-features --target x86_64-unknown-freebsd
for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu aarch64-linux-android x86_64-linux-android; do
    cross test --all-features --target "$target"
done
cargo test --all-features
