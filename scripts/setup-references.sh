#!/bin/bash
# Setup script for reference implementation submodules

set -e  # Exit on error

echo "Setting up reference implementation submodules..."

# Define the submodules with their repository URLs
declare -A SUBMODULES=(
    # Binary analysis frameworks
    ["reference/angr"]="https://github.com/angr/angr.git"
    ["reference/cle"]="https://github.com/angr/cle.git"
    ["reference/claripy"]="https://github.com/angr/claripy.git"
    ["reference/ghidra"]="https://github.com/NationalSecurityAgency/ghidra.git"
    ["reference/radare2"]="https://github.com/radareorg/radare2.git"
    ["reference/rizin"]="https://github.com/rizinorg/rizin.git"
    ["reference/REDasm"]="https://github.com/REDasmOrg/REDasm.git"
    
    # Binary instrumentation and emulation
    ["reference/LIEF"]="https://github.com/lief-project/LIEF.git"
    ["reference/unicorn"]="https://github.com/unicorn-engine/unicorn.git"
    ["reference/Triton"]="https://github.com/JonathanSalwan/Triton.git"
    
    # Symbolic execution
    ["reference/manticore"]="https://github.com/trailofbits/manticore.git"
    ["reference/symbolic"]="https://github.com/getsentry/symbolic.git"
    
    # Malware analysis and detection
    ["reference/capa"]="https://github.com/mandiant/capa.git"
    ["reference/Detect-It-Easy"]="https://github.com/horsicq/Detect-It-Easy.git"
    ["reference/binary-inspector"]="https://github.com/aboutcode-org/binary-inspector.git"
    
    # Debugging tools
    ["reference/pwndbg"]="https://github.com/pwndbg/pwndbg.git"
    ["reference/HyperDbg"]="https://github.com/HyperDbg/HyperDbg.git"
    
    # Other tools
    ["reference/pharos"]="https://github.com/cmu-sei/pharos.git"
)

# Function to add a submodule if it doesn't exist
add_submodule() {
    local path=$1
    local url=$2
    
    if [ -d "$path/.git" ]; then
        echo "✓ Submodule $path already exists"
    else
        echo "Adding submodule: $path"
        git submodule add "$url" "$path"
        echo "✓ Added $path"
    fi
}

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "Error: Not in a git repository"
    exit 1
fi

# Add each submodule
for path in "${!SUBMODULES[@]}"; do
    add_submodule "$path" "${SUBMODULES[$path]}"
done

echo ""
echo "Initializing and updating submodules..."
git submodule update --init --recursive

echo ""
echo "✅ Reference implementations setup complete!"
echo ""
echo "Submodules added:"
for path in "${!SUBMODULES[@]}"; do
    echo "  - $path"
done

echo ""
echo "To update submodules in the future, run:"
echo "  git submodule update --remote --merge"