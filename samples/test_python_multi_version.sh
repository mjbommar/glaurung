#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/source"
OUTPUT_DIR="$SCRIPT_DIR/test_output"
PYTHON_SOURCE="$SOURCE_DIR/python/hello.py"

echo "Testing multi-version Python bytecode generation..."
echo "Source: $PYTHON_SOURCE"
echo "Output: $OUTPUT_DIR/python"

# Python versions to test
PYTHON_VERSIONS=("3.8" "3.9" "3.10" "3.11" "3.12" "3.13")

for version in "${PYTHON_VERSIONS[@]}"; do
    echo "Testing Python $version..."
    
    # Find the Python executable
    PYTHON_EXE=$(uv python find "$version" 2>/dev/null || echo "")
    
    if [ -n "$PYTHON_EXE" ] && [ -x "$PYTHON_EXE" ]; then
        echo "  Found Python $version at: $PYTHON_EXE"
        
        # Clean __pycache__
        rm -rf "$(dirname "$PYTHON_SOURCE")/__pycache__"
        
        # Compile regular bytecode
        echo "  Compiling regular bytecode..."
        "$PYTHON_EXE" -m py_compile "$PYTHON_SOURCE"
        
        # Find and copy the .pyc file
        PYC_FILE=$("$PYTHON_EXE" -c "
import sys, pathlib
p = pathlib.Path('$PYTHON_SOURCE')
pyc_files = list(p.parent.glob('__pycache__/' + p.stem + '.*.pyc'))
if pyc_files:
    print(pyc_files[0])
else:
    print('')
" 2>/dev/null)
        
        if [ -n "$PYC_FILE" ] && [ -f "$PYC_FILE" ]; then
            cp "$PYC_FILE" "$OUTPUT_DIR/python/hello-py${version}.pyc"
            echo "  ✓ Created: hello-py${version}.pyc"
            
            # Show magic number
            MAGIC=$(hexdump -C "$OUTPUT_DIR/python/hello-py${version}.pyc" | head -1 | awk '{print $2$3$4$5}')
            echo "  Magic number: $MAGIC"
        else
            echo "  ✗ Failed to find .pyc file"
        fi
        
        # Clean up
        rm -rf "$(dirname "$PYTHON_SOURCE")/__pycache__"
    else
        echo "  ✗ Python $version not found"
    fi
    echo ""
done

echo "Generated files:"
ls -la "$OUTPUT_DIR/python/" 2>/dev/null || echo "No files generated"
