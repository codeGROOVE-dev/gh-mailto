
# BEGIN: lint-install .
# http://github.com/codeGROOVE-dev/lint-install

.PHONY: lint
lint: _lint

LINT_ARCH := $(shell uname -m)
LINT_OS := $(shell uname)
LINT_OS_LOWER := $(shell echo $(LINT_OS) | tr '[:upper:]' '[:lower:]')
LINT_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# shellcheck and hadolint lack arm64 native binaries: rely on x86-64 emulation
ifeq ($(LINT_OS),Darwin)
	ifeq ($(LINT_ARCH),arm64)
		LINT_ARCH=x86_64
	endif
endif

LINTERS :=
FIXERS :=

SHELLCHECK_VERSION ?= v0.10.0
SHELLCHECK_BIN := $(LINT_ROOT)/out/linters/shellcheck-$(SHELLCHECK_VERSION)-$(LINT_ARCH)
$(SHELLCHECK_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	curl -sSfL -o $@.tar.xz https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/shellcheck-$(SHELLCHECK_VERSION).$(LINT_OS_LOWER).$(LINT_ARCH).tar.xz \
		|| echo "Unable to fetch shellcheck for $(LINT_OS)/$(LINT_ARCH): falling back to locally install"
	test -f $@.tar.xz \
		&& tar -C $(LINT_ROOT)/out/linters -xJf $@.tar.xz \
		&& mv $(LINT_ROOT)/out/linters/shellcheck-$(SHELLCHECK_VERSION)/shellcheck $@ \
		|| printf "#!/usr/bin/env shellcheck\n" > $@
	chmod u+x $@

LINTERS += shellcheck-lint
shellcheck-lint: $(SHELLCHECK_BIN)
	$(SHELLCHECK_BIN) $(shell find . -name "*.sh")

FIXERS += shellcheck-fix
shellcheck-fix: $(SHELLCHECK_BIN)
	$(SHELLCHECK_BIN) $(shell find . -name "*.sh") -f diff | { read -t 1 line || exit 0; { echo "$$line" && cat; } | git apply -p2; }

GOLANGCI_LINT_CONFIG := $(LINT_ROOT)/.golangci.yml
GOLANGCI_LINT_VERSION ?= v2.5.0
GOLANGCI_LINT_BIN := $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)
$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $@

LINTERS += golangci-lint-lint
golangci-lint-lint: $(GOLANGCI_LINT_BIN)
	find . -name go.mod -execdir "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" \;

FIXERS += golangci-lint-fix
golangci-lint-fix: $(GOLANGCI_LINT_BIN)
	find . -name go.mod -execdir "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" --fix \;

YAMLLINT_VERSION ?= 1.37.1
YAMLLINT_ROOT := $(LINT_ROOT)/out/linters/yamllint-$(YAMLLINT_VERSION)
YAMLLINT_BIN := $(YAMLLINT_ROOT)/dist/bin/yamllint
$(YAMLLINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/yamllint-*
	curl -sSfL https://github.com/adrienverge/yamllint/archive/refs/tags/v$(YAMLLINT_VERSION).tar.gz | tar -C $(LINT_ROOT)/out/linters -zxf -
	cd $(YAMLLINT_ROOT) && pip3 install --target dist . || pip install --target dist .

LINTERS += yamllint-lint
yamllint-lint: $(YAMLLINT_BIN)
	PYTHONPATH=$(YAMLLINT_ROOT)/dist $(YAMLLINT_ROOT)/dist/bin/yamllint .

BIOME_VERSION ?= 2.2.6
BIOME_BIN := $(LINT_ROOT)/out/linters/biome-$(BIOME_VERSION)-$(LINT_ARCH)
BIOME_CONFIG := $(LINT_ROOT)/biome.json

# Map architecture names for Biome downloads
BIOME_ARCH := $(LINT_ARCH)
ifeq ($(LINT_ARCH),x86_64)
	BIOME_ARCH := x64
endif

$(BIOME_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/biome-*
	curl -sSfL -o $@ https://github.com/biomejs/biome/releases/download/%40biomejs%2Fbiome%40$(BIOME_VERSION)/biome-$(LINT_OS_LOWER)-$(BIOME_ARCH) \
		|| echo "Unable to fetch biome for $(LINT_OS_LOWER)/$(BIOME_ARCH), falling back to local install"
	test -f $@ || printf "#!/usr/bin/env biome\n" > $@
	chmod u+x $@

LINTERS += biome-lint
biome-lint: $(BIOME_BIN)
	$(BIOME_BIN) check --config-path=$(BIOME_CONFIG) .

FIXERS += biome-fix
biome-fix: $(BIOME_BIN)
	$(BIOME_BIN) check --write --config-path=$(BIOME_CONFIG) .

.PHONY: _lint $(LINTERS)
_lint:
	@exit_code=0; \
	for target in $(LINTERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

.PHONY: fix $(FIXERS)
fix:
	@exit_code=0; \
	for target in $(FIXERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

# END: lint-install .


# Test targets
.PHONY: test
test: test-coverage

.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test ./... -coverprofile=coverage.out -covermode=atomic -v
	@echo "\n=== Coverage Summary ==="
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'
	@echo "\n=== Package Coverage ==="
	@go tool cover -func=coverage.out | grep -E "^(github.com|total)" | grep -v "\.go:" || true
	@echo "\n=== Checking 80% threshold (pkg packages only) ==="
	@failed=0; \
	for pkg in $$(go list ./pkg/...); do \
		coverage=$$(go test -coverprofile=/tmp/coverage_$$$$.out -covermode=atomic -short -timeout 30s $$pkg 2>/dev/null | grep coverage | sed 's/.*coverage: \([0-9.]*\)%.*/\1/'); \
		if [ -n "$$coverage" ]; then \
			result=$$(echo "$$coverage < 80" | bc -l 2>/dev/null || echo "1"); \
			if [ "$$result" = "1" ]; then \
				printf "❌ %-60s %6.1f%% (below 80%%)\n" "$$pkg" "$$coverage"; \
				failed=1; \
			else \
				printf "✅ %-60s %6.1f%%\n" "$$pkg" "$$coverage"; \
			fi; \
		fi; \
	done; \
	rm -f /tmp/coverage_*.out; \
	echo "\n=== CMD packages (no threshold requirement) ==="; \
	for pkg in $$(go list ./cmd/...); do \
		coverage=$$(go test -coverprofile=/tmp/coverage_$$$$.out -covermode=atomic -short -timeout 30s $$pkg 2>/dev/null | grep coverage | sed 's/.*coverage: \([0-9.]*\)%.*/\1/'); \
		if [ -n "$$coverage" ]; then \
			printf "ℹ️  %-60s %6.1f%%\n" "$$pkg" "$$coverage"; \
		else \
			printf "ℹ️  %-60s %6s\n" "$$pkg" "N/A"; \
		fi; \
	done; \
	rm -f /tmp/coverage_*.out; \
	if [ $$failed -eq 1 ]; then \
		echo "\n❌ Some pkg packages are below 80% coverage threshold"; \
		exit 1; \
	else \
		echo "\n✅ All pkg packages meet 80% coverage threshold"; \
	fi

.PHONY: test-html
test-html: test-coverage
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
