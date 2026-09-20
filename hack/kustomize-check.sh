#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Every committed base must equal a fresh render of the chart.
check_base() {
  local name=$1 mode=$2
  shift 2
  hack/gen-kustomize.sh "$tmp/$name" "$@"
  diff -ru "kustomize/$name" "$tmp/$name"
  kustomize build "kustomize/$name" > "$tmp/$name.yaml"
  yq -o=json -I0 '.' "$tmp/$name.yaml" | bin/trcs lint-manifests --mode "$mode"
  printf 'PASS kustomize base %s has no drift and passes policy (%s)\n' "$name" "$mode"
}
check_base base standard kustomize/helm-values-for-base.yaml
check_base coco-snp coco kustomize/helm-values-for-base.yaml examples/values-coco-snp.yaml
check_base coco-tdx coco kustomize/helm-values-for-base.yaml examples/values-coco-tdx.yaml
kustomize build kustomize/overlays/dev > "$tmp/dev.yaml"
yq -o=json -I0 '.' "$tmp/dev.yaml" | bin/trcs lint-manifests --mode standard
printf 'PASS kustomize overlay dev (standard)\n'
