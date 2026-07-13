#!/usr/bin/env bash
# Rebuild the SELinux binary-policy fixtures from pol.cil.
# Requires secilc (apt: secilc). Produces real kernel policydb blobs at
# several versions (Android 12-15 use 30-33; upstream is 35).
set -euo pipefail
cd "$(dirname "$0")"
for v in 30 33 35; do
  secilc -m -M true -c "$v" -o "sepolicy.$v" pol.cil
done
echo "built: sepolicy.30 sepolicy.33 sepolicy.35"
# Non-MLS variant (simpler traversal) for the avtab-oracle follow-up.
secilc -m -M false -c 33 -o sepolicy_nomls.33 pol_nomls.cil
echo "built: sepolicy_nomls.33"
