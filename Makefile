# CI/CD for hanzoai/platform (the Hanzo PaaS) — NOT GitHub Actions.
# The platform runs `make ci` as a build step and/or a scheduled (cron) task.
# Works identically locally and anywhere: `make ci`.
SHELL := /usr/bin/env bash
export GOPRIVATE := github.com/hanzoai,github.com/luxfi
export GOFLAGS  := -mod=mod
BIN  := $(CURDIR)/.bin
export PATH := $(BIN):$(PATH)
GITLEAKS_VERSION ?= 8.21.2
ARCH := $(shell uname -m | sed 's/x86_64/x64/; s/aarch64/arm64/')

.PHONY: ci build test scan vuln secrets sbom tools clean
ci: build test scan            ## full pipeline (build -> test -> scan)
build:
	go build ./...
test:
	go test ./...
scan: vuln secrets sbom
vuln:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...
secrets: $(BIN)/gitleaks
	gitleaks detect --source . --redact --no-banner --exit-code 1
sbom: $(BIN)/syft
	syft . -o cyclonedx-json=sbom.cyclonedx.json -q
tools: $(BIN)/gitleaks $(BIN)/syft
clean:
	rm -rf $(BIN) sbom.cyclonedx.json

$(BIN)/gitleaks:
	@mkdir -p $(BIN)
	curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v$(GITLEAKS_VERSION)/gitleaks_$(GITLEAKS_VERSION)_linux_$(ARCH).tar.gz" | tar -xz -C $(BIN) gitleaks
$(BIN)/syft:
	@mkdir -p $(BIN)
	curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b $(BIN) >/dev/null
