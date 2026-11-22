#!/usr/bin/env bash
set -euo pipefail

targets=(
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
    x86_64-unknown-freebsd
    aarch64-linux-android
    x86_64-linux-android
)

for target in "${targets[@]}"; do
    cross build --all-features --target "$target"
done
