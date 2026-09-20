SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
VERSION ?= 0.1.0
IMAGE ?= ghcr.io/lore-hex/trcs:$(VERSION)
GO ?= go
CHART := charts/confidential-inference
EXAMPLES := $(sort $(wildcard examples/values-*.yaml))
# Set KUBECONFORM=skip for offline validation; CI runs schema validation online.
export KUBECONFORM
.PHONY: test lint build image chart-lint render manifests-lint kustomize kustomize-check guardrail-tests e2e-kind all

test:
	$(GO) test -race ./...

lint:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
	$(GO) vet ./...
	shellcheck hack/*.sh

build:
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '-s -w -buildid= -X main.version=$(VERSION)' -o bin/trcs ./cmd/trcs
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '-s -w -buildid=' -o bin/trcs-helm-test ./cmd/trcs-helm-test

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

chart-lint:
	@for values in $(EXAMPLES); do helm lint $(CHART) -f "$$values"; done

render:
	@mkdir -p build/rendered
	@for values in $(EXAMPLES); do name=$$(basename "$$values" .yaml); helm template trcs $(CHART) -f "$$values" > "build/rendered/$$name.yaml"; printf 'PASS render %s\n' "$$name"; done

manifests-lint: build render
	@hack/lint-manifests.sh

kustomize:
	@hack/gen-kustomize.sh

kustomize-check: build
	@hack/kustomize-check.sh

guardrail-tests:
	@hack/chart-guardrail-tests.sh

e2e-kind:
	@hack/e2e-kind.sh

all: lint test build chart-lint manifests-lint guardrail-tests kustomize-check
