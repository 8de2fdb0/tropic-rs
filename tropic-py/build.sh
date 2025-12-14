#!/bin/bash
# Build script for tropic-py

set -e

echo "=== Building tropic-py ==="
cd "$(dirname "$0")"

# Check if maturin is installed
if ! command -v maturin &> /dev/null; then
    echo "Error: maturin not found. Install with: pip install maturin"
    exit 1
fi

# Build the package
echo "Building Python package..."
maturin build --release

echo ""
echo "=== Build successful! ==="
echo ""
echo "To install the package:"
echo "  pip install target/wheels/tropic_py-*.whl"
echo ""
echo "Or for development:"
echo "  maturin develop"
