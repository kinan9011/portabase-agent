#!/usr/bin/env bash
# Markers <-> registry consistency (W01, ARCH-22: hooks are anchored by symbol, never by line number).
#   - every `FORK(stack-recovery)` marker outside fork-only paths must be `FORK(stack-recovery): Axx <reason>`,
#     Axx must exist in scripts/fork/patch-registry.txt and the file must be the registered one;
#   - every registry row: file exists, anchor symbol present, marker count equals the registered count.
# Env (tests): PATCH_ROOT (repo root), PATCH_REGISTRY (registry file).
set -euo pipefail

ROOT="${PATCH_ROOT:-$(git rev-parse --show-toplevel)}"
REG="${PATCH_REGISTRY:-$ROOT/scripts/fork/patch-registry.txt}"
cd "$ROOT"

FORK_ONLY='^(src/fork/|scripts/fork/|docs/fork/|\.github/workflows/fork-)'
fail=0
err() { echo "check-patches: $*" >&2; fail=1; }

[ -f "$REG" ] || { echo "check-patches: registry not found: $REG" >&2; exit 2; }

declare -A found=()   # "id|file" -> count
declare -A rows=()    # "id" -> file
declare -A expect=()  # "id" -> markers
nrows=0

while IFS='|' read -r id file anchor markers; do
  id="${id//[[:space:]]/}"
  [[ -z "$id" || "$id" == \#* ]] && continue
  nrows=$((nrows + 1))
  rows[$id]="$file"; expect[$id]="${markers//[[:space:]]/}"
  if [ ! -f "$file" ]; then err "$id: registered file missing: $file"; continue; fi
  grep -qF -- "$anchor" "$file" || err "$id: anchor symbol '$anchor' not found in $file"
done < "$REG"

nmarkers=0
while IFS= read -r hit; do
  file="${hit%%:*}"; rest="${hit#*:}"; rest="${rest#*:}"
  [[ "$file:" =~ $FORK_ONLY ]] && continue
  nmarkers=$((nmarkers + 1))
  if [[ "$rest" =~ FORK\(stack-recovery\):\ ([AP][0-9]+)([^0-9]|$) ]]; then
    id="${BASH_REMATCH[1]}"
    if [ -z "${rows[$id]+x}" ]; then err "marker $id in $file is not in the registry"
    elif [ "${rows[$id]}" != "$file" ]; then err "marker $id found in $file but registered for ${rows[$id]}"
    else found["$id|$file"]=$(( ${found["$id|$file"]:-0} + 1 )); fi
  else
    err "marker without a registry id (expected 'FORK(stack-recovery): Axx <reason>') in $file: ${rest:0:80}"
  fi
done < <(grep -rIn --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=.git --exclude-dir=.plan-review --exclude-dir=private --exclude-dir=target --exclude-dir=coverage -e 'FORK(stack-recovery)' . | sed 's|^\./||')

for id in "${!rows[@]}"; do
  want="${expect[$id]}"; [ "$want" = "-" ] && continue
  got="${found["$id|${rows[$id]}"]:-0}"
  [ "$got" = "$want" ] || err "$id: expected $want marker(s) in ${rows[$id]}, found $got"
done

if [ "$fail" -ne 0 ]; then echo "check-patches: FAILED" >&2; exit 1; fi
echo "check-patches: OK ($nrows registered patches, $nmarkers markers)"
