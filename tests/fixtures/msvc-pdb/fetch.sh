#!/bin/bash
# Populate tests/fixtures/msvc-pdb/ from msdl.microsoft.com per MANIFEST.json.
#
# We do not commit the PE + PDB bytes (~78 MB total) -- this script
# reproduces them on demand for the #179 PDB ingestion test suite.
#
# After fetch:
#   tests/fixtures/msvc-pdb/<binary>          # PE32+ x86-64
#   tests/fixtures/msvc-pdb/<pdb_name>        # matching PDB
#
# Idempotent: skips files whose PE CodeView GUID already matches
# MANIFEST. NOTE: we verify the PDB GUID embedded in the PE, NOT
# the PE's sha256. msdl.microsoft.com re-signs binaries from time
# to time without updating PDB GUID; the (PE, PDB) pair remains
# internally consistent (same GUID + age both sides) even if the
# PE sha256 drifts. See README.md for the long version.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${SCRIPT_DIR}/MANIFEST.json"

if [[ ! -f "${MANIFEST}" ]]; then
    echo "missing MANIFEST.json at ${MANIFEST}" >&2
    exit 1
fi

if ! command -v python3 >/dev/null; then
    echo "python3 required" >&2
    exit 1
fi

# Find the PE CodeView extractor.
EXTRACTOR=""
for cand in \
    "${SCRIPT_DIR}/../../scripts/extract_pdb_id.py" \
    "${SCRIPT_DIR}/extract_pdb_id.py" \
    "/nas4/data/workspace-infosec/agentic-security-bot/tools/windows/win11-fuzz/scripts/lib/extract_pdb_id.py" \
    ; do
    if [[ -f "$cand" ]]; then
        EXTRACTOR="$cand"
        break
    fi
done
if [[ -z "${EXTRACTOR}" ]]; then
    echo "warning: no extract_pdb_id.py found; PE GUID verification disabled" >&2
fi

verify_pe_guid() {
    local pe="$1" want_guid="$2" want_age="$3"
    [[ -f "${pe}" ]] || return 1
    [[ -z "${EXTRACTOR}" ]] && return 0   # cannot verify; assume ok
    local out got_guid got_age
    out=$(python3 "${EXTRACTOR}" "${pe}" 2>/dev/null) || return 1
    # output: "<pdbname> <GUID-uppercase-32hex> <AGE-hex>"
    got_guid=$(echo "$out" | awk '{print $2}')
    got_age=$(echo "$out" | awk '{print $3}')
    [[ "${got_guid^^}" == "${want_guid^^}" && "${got_age^^}" == "${want_age^^}" ]]
}

fetch_one() {
    local url="$1" dest="$2"
    echo "fetch: ${url}" >&2
    if ! curl -fsSL --retry 3 -o "${dest}.tmp" "${url}"; then
        echo "FAIL: ${url}" >&2
        rm -f "${dest}.tmp"
        return 1
    fi
    mv "${dest}.tmp" "${dest}"
    echo "ok: $(basename "${dest}")" >&2
}

# Extract fetch list from MANIFEST.
python3 - "${MANIFEST}" <<'PY' > "${SCRIPT_DIR}/.fetch_list"
import json, sys
m = json.load(open(sys.argv[1]))
for fx in m["fixtures"]:
    print("\t".join([
        fx["binary"],
        fx["pdb_name"],
        fx["pdb_guid"],
        f'{fx["pdb_age"]:X}',
        fx["msdl_pe_url"],
        fx["msdl_pdb_url"],
    ]))
PY

ok=0
fail=0
while IFS=$'\t' read -r binary pdb_name pdb_guid pdb_age pe_url pdb_url; do
    pe_path="${SCRIPT_DIR}/${binary}"
    pdb_path="${SCRIPT_DIR}/${pdb_name}"

    # PE: verify by PDB GUID embedded in CodeView, not by sha256.
    if verify_pe_guid "${pe_path}" "${pdb_guid}" "${pdb_age}"; then
        echo "ok (cached, GUID match): ${binary}" >&2
    else
        if ! fetch_one "${pe_url}" "${pe_path}"; then
            fail=$((fail + 1))
            continue
        fi
        if ! verify_pe_guid "${pe_path}" "${pdb_guid}" "${pdb_age}"; then
            echo "GUID MISMATCH after fetch: ${binary}" >&2
            echo "  want pdb_guid: ${pdb_guid}, age ${pdb_age}" >&2
            rm -f "${pe_path}"
            fail=$((fail + 1))
            continue
        fi
    fi

    # PDB: content-addressed by URL, just fetch (skip if present + non-empty).
    if [[ -s "${pdb_path}" ]]; then
        echo "ok (cached): ${pdb_name}" >&2
    else
        if ! fetch_one "${pdb_url}" "${pdb_path}"; then
            fail=$((fail + 1))
            continue
        fi
    fi

    ok=$((ok + 1))
done < "${SCRIPT_DIR}/.fetch_list"

rm -f "${SCRIPT_DIR}/.fetch_list"

echo "" >&2
echo "fetch summary: ${ok} ok, ${fail} failed" >&2
if [[ "${fail}" -gt 0 ]]; then
    exit 5
fi
