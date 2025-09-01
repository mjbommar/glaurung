#!/bin/bash

# Kernel module collection script
# Collects sample kernel modules from the host system for analysis

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR/../binaries/kernel-modules}"
METADATA_DIR="${OUTPUT_DIR}/metadata"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[COLLECT] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

ensure_dir() { [ -d "$1" ] || mkdir -p "$1"; }

# Check if running on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    warn "This script only works on Linux systems"
    exit 1
fi

# Create output directories
ensure_dir "$OUTPUT_DIR"
ensure_dir "$METADATA_DIR"

log "Collecting kernel modules from system..."

# Get kernel version
KERNEL_VERSION=$(uname -r)
info "Kernel version: $KERNEL_VERSION"

# Common kernel module locations
MODULE_PATHS=(
    "/lib/modules/$KERNEL_VERSION/kernel"
    "/lib/modules/$KERNEL_VERSION/updates"
    "/lib/modules/$KERNEL_VERSION/extra"
)

# Categories to collect (limit to avoid huge collections)
CATEGORIES=(
    "drivers/net/ethernet"     # Network drivers
    "drivers/usb/storage"      # USB storage
    "drivers/block"            # Block devices
    "fs"                       # Filesystems
    "crypto"                   # Crypto modules
    "drivers/gpu/drm"         # Graphics
    "sound/core"              # Sound core
    "drivers/hid"             # HID devices
)

# Counter for collected modules
COUNT=0
MAX_MODULES=50  # Limit number of modules to collect

# Function to collect a module
collect_module() {
    local module_path="$1"
    local category="$2"
    local filename=$(basename "$module_path")
    local name="${filename%.ko*}"
    
    # Create category directory
    local cat_dir="$OUTPUT_DIR/$category"
    ensure_dir "$cat_dir"
    
    # Copy module
    if cp "$module_path" "$cat_dir/$filename" 2>/dev/null; then
        log "Collected: $category/$filename"
        
        # Generate metadata
        local meta_file="$METADATA_DIR/${name}.json"
        local file_info=$(file "$module_path" 2>/dev/null || echo "Unknown")
        local size=$(stat -c%s "$module_path" 2>/dev/null || echo "0")
        local modinfo_output=$(modinfo "$module_path" 2>/dev/null || echo "{}")
        
        cat > "$meta_file" <<EOF
{
  "name": "$name",
  "filename": "$filename",
  "category": "$category",
  "source_path": "$module_path",
  "kernel_version": "$KERNEL_VERSION",
  "size_bytes": $size,
  "file_type": "$file_info",
  "collected_at": "$(date -Iseconds)",
  "platform": "$(uname -m)",
  "modinfo": {
    "description": "$(modinfo "$module_path" 2>/dev/null | grep '^description:' | cut -d: -f2- | xargs || echo "")",
    "author": "$(modinfo "$module_path" 2>/dev/null | grep '^author:' | cut -d: -f2- | xargs || echo "")",
    "license": "$(modinfo "$module_path" 2>/dev/null | grep '^license:' | cut -d: -f2- | xargs || echo "")",
    "vermagic": "$(modinfo "$module_path" 2>/dev/null | grep '^vermagic:' | cut -d: -f2- | xargs || echo "")"
  }
}
EOF
        ((COUNT++))
        return 0
    else
        return 1
    fi
}

# Collect modules from each category
for base_path in "${MODULE_PATHS[@]}"; do
    if [[ ! -d "$base_path" ]]; then
        continue
    fi
    
    for category in "${CATEGORIES[@]}"; do
        local search_path="$base_path/$category"
        if [[ ! -d "$search_path" ]]; then
            continue
        fi
        
        info "Searching in $search_path..."
        
        # Find .ko and .ko.xz files
        while IFS= read -r module_file; do
            if [[ $COUNT -ge $MAX_MODULES ]]; then
                warn "Reached maximum module limit ($MAX_MODULES)"
                break 2
            fi
            
            # Handle compressed modules
            if [[ "$module_file" == *.ko.xz ]]; then
                # Create temp uncompressed version
                temp_file="/tmp/$(basename "${module_file%.xz}")"
                if xz -dc "$module_file" > "$temp_file" 2>/dev/null; then
                    collect_module "$temp_file" "$category"
                    rm -f "$temp_file"
                fi
            else
                collect_module "$module_file" "$category"
            fi
        done < <(find "$search_path" -maxdepth 2 -name "*.ko" -o -name "*.ko.xz" 2>/dev/null | head -10)
    done
done

# Also collect some currently loaded modules
info "Collecting currently loaded modules..."
LOADED_DIR="$OUTPUT_DIR/loaded"
ensure_dir "$LOADED_DIR"

lsmod | tail -n +2 | head -10 | while read -r module_name _; do
    if [[ $COUNT -ge $MAX_MODULES ]]; then
        break
    fi
    
    # Find the module file
    module_file=$(modinfo -F filename "$module_name" 2>/dev/null || true)
    if [[ -n "$module_file" && -f "$module_file" ]]; then
        collect_module "$module_file" "loaded"
    fi
done

# Create an index file
INDEX_FILE="$OUTPUT_DIR/index.json"
log "Creating index file..."

cat > "$INDEX_FILE" <<EOF
{
  "kernel_version": "$KERNEL_VERSION",
  "platform": "$(uname -m)",
  "os": "$(uname -s)",
  "collected_at": "$(date -Iseconds)",
  "total_modules": $COUNT,
  "categories": [
$(find "$OUTPUT_DIR" -type d -mindepth 1 -maxdepth 1 ! -name metadata -exec basename {} \; | \
    awk '{printf "    \"%s\"", $0} END{print ""}' | sed 's/,$//')
  ]
}
EOF

log "Collection complete! Collected $COUNT kernel modules"
info "Output directory: $OUTPUT_DIR"
info "Metadata directory: $METADATA_DIR"

# Optionally compress the collection
if command -v tar &> /dev/null; then
    ARCHIVE="$OUTPUT_DIR/../kernel-modules-$(date +%Y%m%d-%H%M%S).tar.gz"
    log "Creating archive: $ARCHIVE"
    tar -czf "$ARCHIVE" -C "$OUTPUT_DIR/.." "$(basename "$OUTPUT_DIR")"
    info "Archive created: $ARCHIVE"
fi