# One-command entry points for common tasks.
#
# Usage: `make <target>`, e.g. `make test`, `make lint`, `make build`.

.PHONY: build test lint fmt check clean changelog changelog-unreleased

## Build the workspace (debug)
build:
	cargo build

## Build the release binary
release:
	cargo build --release

## Run the full test suite
test:
	cargo test

## Lint with clippy (deny warnings)
lint:
	cargo clippy --all-targets --all-features -- -D warnings

## Check formatting
fmt:
	cargo fmt --check

## Format code in place
fmt-fix:
	cargo fmt

## Run all checks (fmt + lint + test)
check: fmt lint test

## Regenerate the full CHANGELOG.md from git history (requires git-cliff)
changelog:
	git-cliff --config cliff.toml --output CHANGELOG.md

## Preview the unreleased changelog entries (requires git-cliff)
changelog-unreleased:
	git-cliff --config cliff.toml --unreleased

## Clean build artifacts
clean:
	cargo clean
