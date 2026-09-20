#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
for file in build/rendered/*.yaml; do
  mode=standard
  case "$file" in *coco*) mode=coco ;; esac
  yq -o=json -I0 '.' "$file" | bin/trcs lint-manifests --mode "$mode"
  if [[ "${KUBECONFORM:-auto}" != skip ]] && command -v kubeconform >/dev/null 2>&1; then
    kubeconform -strict -summary -ignore-missing-schemas "$file"
  fi
  printf 'PASS manifests %s (%s)\n' "$file" "$mode"
done
