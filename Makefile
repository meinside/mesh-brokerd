# brokerd's quality gate: gofmt, go vet, golangci-lint,
# go test ./... — `make check` runs all four, and must pass before any
# change is considered done.
#
# CGO_ENABLED=1 is required: internal/storage uses mattn/go-sqlite3
# (cgo binding to the real SQLite C library), a deliberate choice over
# a pure-Go driver for this project's low-throughput write workload
# (see the driver-choice discussion recorded alongside this decision).
export CGO_ENABLED=1

GOFILES := $(shell find . -name '*.go' -not -path './.git/*')

# Binary name matches what `go install <module>@latest` produces, so the
# artifact is called the same thing however it was built.
BINARY := mesh-brokerd

.PHONY: check check-commit fmt fmt-check vet lint test build clean

check: fmt-check vet lint test

fmt:
	gofmt -w $(GOFILES)

fmt-check:
	@unformatted="$$(gofmt -l $(GOFILES))"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needs to be run on:"; echo "$$unformatted"; exit 1; \
	fi

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# Every test here runs with no external secret or network dependency.
# Tests that genuinely need either are isolated behind build tags and
# excluded from this target: `tls_e2e` (real ACME/DNS round trip, see
# docs/runbook.md §3) and `diag` (reads a live brokerd database).
test:
	go test ./... -count=1

# Verify that what is *committed* builds, not just what is in the working
# tree. Every other gate here reads the working tree, so none of them can see
# a source file that exists locally and was never committed -- which is
# exactly what happened when a global ignore pattern (`storage/` in
# ~/.gitignore) silently excluded the whole internal/storage package while
# `make check` stayed green. Kept separate from `check` because it needs a
# commit to exist.
check-commit:
	@tmp=$$(mktemp -d); \
	git archive HEAD | tar -x -C $$tmp; \
	CGO_ENABLED=1 go build -C $$tmp ./...; rc=$$?; \
	find $$tmp -mindepth 1 -delete; rmdir $$tmp; \
	if [ $$rc -eq 0 ]; then echo "committed tree builds"; else echo "COMMITTED TREE DOES NOT BUILD"; fi; \
	exit $$rc

build:
	go build -o bin/$(BINARY) .

clean:
	rm -rf bin/
