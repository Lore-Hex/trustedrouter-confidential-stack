#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cluster="trcs-e2e-$$"
namespace=trcs-e2e
tmp=$(mktemp -d)
forward_pid=
created=false
cleanup() {
  if [[ -n "$forward_pid" ]]; then
    kill "$forward_pid" 2>/dev/null || true
    wait "$forward_pid" 2>/dev/null || true
  fi
  if [[ "$created" == true ]]; then
    kind delete cluster --name "$cluster"
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT
# Keep context isolated from the user's kubeconfig.
export KUBECONFIG="$tmp/kubeconfig"
created=true
kind create cluster --name "$cluster" --kubeconfig "$KUBECONFIG" --wait 120s
docker build --build-arg VERSION=0.1.0 -t trcs-e2e:local .
kind load docker-image trcs-e2e:local --name "$cluster"
kubectl create namespace "$namespace"
kubectl -n "$namespace" create configmap trcs-stub --from-file=server.py=hack/stub-openai/server.py
helm install e2e charts/confidential-inference -n "$namespace" \
  -f examples/values-e2e-stub.yaml --wait --timeout 5m
kubectl -n "$namespace" rollout status deployment/e2e-confidential-inference --timeout=180s
helm test e2e -n "$namespace" --logs --timeout 180s
kubectl -n "$namespace" port-forward service/e2e-confidential-inference :443 > "$tmp/forward.log" 2>&1 &
forward_pid=$!
port=
for _ in {1..100}; do
  port=$(sed -nE 's/.*127\.0\.0\.1:([0-9]+) -> .*/\1/p' "$tmp/forward.log" | head -n 1)
  if [[ -n "$port" ]]; then break; fi
  if ! kill -0 "$forward_pid" 2>/dev/null; then cat "$tmp/forward.log" >&2; exit 1; fi
  sleep 0.1
done
if [[ -z "$port" ]]; then printf 'port-forward did not become ready\n' >&2; exit 1; fi
make build
bin/trcs check-endpoint "https://127.0.0.1:$port" --expect-tee none --json
python3 - "$port" <<'PY'
import http.client
import json
import ssl
import sys
import time

# This is a standard-mode plumbing test, not a confidentiality assertion.
connection = http.client.HTTPSConnection("127.0.0.1", int(sys.argv[1]),
    context=ssl._create_unverified_context(), timeout=10)
request = json.dumps({"model": "stub", "messages": [{"role": "user", "content": "hi"}], "stream": True})
connection.request("POST", "/v1/chat/completions", request, {"Content-Type": "application/json"})
response = connection.getresponse()
assert response.status == 200, response.status
arrivals, done, usage = [], False, False
for raw in response:
    if not raw.startswith(b"data: "):
        continue
    arrivals.append(time.monotonic())
    data = raw[6:].strip()
    if data == b"[DONE]":
        done = True
        break
    chunk = json.loads(data)
    usage = usage or "usage" in chunk
connection.close()
assert done and usage and len(arrivals) >= 5, "missing SSE chunks, usage or DONE"
assert arrivals[-1] - arrivals[0] >= 0.35, "SSE was buffered instead of delivered incrementally"
print("PASS kind e2e: binding, SSE incremental delivery, usage and [DONE]")
PY
