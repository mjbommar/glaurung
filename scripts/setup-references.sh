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
    ["reference/miasm"]="https://github.com/cea-sec/miasm.git"

    # Disassembly / Assembly
    ["reference/capstone"]="https://github.com/capstone-engine/capstone.git"
    ["reference/keystone"]="https://github.com/keystone-engine/keystone.git"
    ["reference/zydis"]="https://github.com/zyantific/zydis.git"
    ["reference/capstone-rs"]="https://github.com/capstone-rust/capstone-rs.git"

    # Binary instrumentation and emulation
    ["reference/LIEF"]="https://github.com/lief-project/LIEF.git"
    ["reference/unicorn"]="https://github.com/unicorn-engine/unicorn.git"
    ["reference/Triton"]="https://github.com/JonathanSalwan/Triton.git"

    # Symbolic execution
    ["reference/manticore"]="https://github.com/trailofbits/manticore.git"

    # Debug Info and Symbolication
    ["reference/symbolic"]="https://github.com/getsentry/symbolic.git"
    ["reference/object"]="https://github.com/gimli-rs/object.git"

    # Decompilers
    ["reference/pycdc"]="https://github.com/zrax/pycdc.git"

    # Constraint solvers
    ["reference/z3"]="https://github.com/Z3Prover/z3.git"

    # Malware analysis and detection
    ["reference/capa"]="https://github.com/mandiant/capa.git"
    ["reference/Detect-It-Easy"]="https://github.com/horsicq/Detect-It-Easy.git"
    ["reference/binary-inspector"]="https://github.com/aboutcode-org/binary-inspector.git"

    # Debugging tools
    ["reference/pwndbg"]="https://github.com/pwndbg/pwndbg.git"
    ["reference/HyperDbg"]="https://github.com/HyperDbg/HyperDbg.git"

    # GUI frontends
    ["reference/Cutter"]="https://github.com/rizinorg/cutter.git"

    # Other tools
    ["reference/pharos"]="https://github.com/cmu-sei/pharos.git"

    # Preprocessing pipeline
    ["reference/alea-preprocess"]="https://github.com/alea-institute/alea-preprocess.git"
)

# Optional script-level submodules (tools, helpers)
declare -A OPTIONAL_SCRIPT_SUBMODULES=(
    ["scripts/capstone-rs"]="https://github.com/capstone-rust/capstone-rs.git"
)

# Function to add a submodule if it doesn't exist
add_submodule() {
    local path=$1
    local url=$2

    # Detect if submodule already exists (handles both .git dir and file)
    if [ -e "$path/.git" ] || git -C "$path" rev-parse --git-dir > /dev/null 2>&1; then
        echo "✓ Submodule $path already exists"
        return 0
    fi

    # Also check if path is already registered in .gitmodules to avoid re-adding
    if git config -f .gitmodules --get-regexp "submodule\.$path\.url" > /dev/null 2>&1; then
        echo "✓ Submodule $path already registered in .gitmodules"
        return 0
    fi

    echo "Adding submodule: $path"
    git submodule add "$url" "$path"
    echo "✓ Added $path"
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

# Add optional script submodules (ignore failures if not desired)
for path in "${!OPTIONAL_SCRIPT_SUBMODULES[@]}"; do
    add_submodule "$path" "${OPTIONAL_SCRIPT_SUBMODULES[$path]}" || true
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
for path in "${!OPTIONAL_SCRIPT_SUBMODULES[@]}"; do
    echo "  - $path"
done

echo ""
echo "To update submodules in the future, run:"
echo "  git submodule update --remote --merge"
