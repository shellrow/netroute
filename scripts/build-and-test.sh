#!/usr/bin/env bash
set -euo pipefail

# target platforms for cross build
TARGETS=(
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
    x86_64-unknown-freebsd
    aarch64-linux-android
    x86_64-linux-android
)

for target in "${TARGETS[@]}"; do
    echo "==> Building for $target..."
    if cross build --target "$target"; then
        echo "Success: $target"
    else
        echo "Failed: $target"
        exit 1
    fi

    echo "==> Testing for $target..."
    if cross test --target "$target"; then
        echo "Tests passed: $target"
    else
        echo "Tests failed: $target"
        exit 1
    fi
done

echo ""
echo "==> Running host tests..."
cargo test

echo ""
echo "==> Running route retrieval test..."
cargo test --test runtime_route -- --nocapture

echo ""
echo "All builds and tests succeeded."
