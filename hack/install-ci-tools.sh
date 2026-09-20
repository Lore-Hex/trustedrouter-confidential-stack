#!/usr/bin/env bash
# Installs the pinned manifest tools CI uses, verifying each download against a
# SHA-256 recorded when the version was chosen. Linux amd64 only (GitHub's
# ubuntu-latest runners). To bump a tool: change its URL and its checksum together.
set -euo pipefail
dest=${1:-/usr/local/bin}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fetch() {
  local name=$1 url=$2 sha=$3 member=${4:-}
  curl -fsSL --retry 3 "$url" -o "$tmp/$name.download"
  echo "$sha  $tmp/$name.download" | sha256sum --check --quiet
  if [[ -n "$member" ]]; then
    tar -xzf "$tmp/$name.download" -C "$tmp" "$member"
    install -m 0755 "$tmp/$member" "$dest/$name"
  else
    install -m 0755 "$tmp/$name.download" "$dest/$name"
  fi
  printf 'installed %s\n' "$name"
}
for tool in "$@"; do :; done
want=${TRCS_CI_TOOLS:-yq kubeconform kustomize kind}
for tool in $want; do
  case "$tool" in
    yq) fetch yq https://github.com/mikefarah/yq/releases/download/v4.53.6/yq_linux_amd64 c5f056448f973ae7d39b5401949648a78f2dc1947d6a8eb65be60d5c504b9385 ;;
    kubeconform) fetch kubeconform https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-amd64.tar.gz 9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883 kubeconform ;;
    kustomize) fetch kustomize https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.8.1/kustomize_v5.8.1_linux_amd64.tar.gz 029a7f0f4e1932c52a0476cf02a0fd855c0bb85694b82c338fc648dcb53a819d kustomize ;;
    kind) fetch kind https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64 aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d ;;
    *) printf 'unknown tool %s\n' "$tool" >&2; exit 1 ;;
  esac
done
