#!/bin/bash

# Cross-compile client for multiple architectures
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "aarch64-unknown-linux-musl"
    "mipsel-unknown-linux-musl" 
    "mips-unknown-linux-musl"
    "powerpc64-unknown-linux-gnu"
    "powerpc-unknown-linux-gnu"
    "armv5te-unknown-linux-musleabi"
    "armv7-unknown-linux-gnueabihf"
)

echo "Building client for multiple architectures..."

for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    if cargo build --release --bin client --target $target; then
        echo "✅ Successfully built for $target"
        # Copy binary with architecture suffix
        cp target/$target/release/client target/client-$target 2>/dev/null || true
    else
        echo "❌ Failed to build for $target"
    fi
done

echo "Build complete. Binaries available in target/ directory"
ls -la target/client-* 2>/dev/null || echo "No cross-compiled binaries found"