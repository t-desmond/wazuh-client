# Contributing to wazuh-client

Thanks for taking the time to contribute! This project is a Rust workspace
that talks to the Wazuh Manager REST API. The guidelines below keep the code
consistent and the review process smooth.

## Table of contents

- [Code of conduct](#code-of-conduct)
- [Getting started](#getting-started)
- [Project layout](#project-layout)
- [Development workflow](#development-workflow)
- [Commit conventions](#commit-conventions)
- [Pull request process](#pull-request-process)
- [Testing](#testing)
- [Style](#style)

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you agree to uphold its standards.

## Getting started

Prerequisites:

- Rust (stable) — install via [rustup](https://rustup.rs)
- `cargo` (comes with rustup)

Clone and build:

```bash
git clone https://github.com/t-desmond/wazuh-client.git
cd wazuh-client
cargo build
```

## Project layout

```
crates/
├── wazuh-core/       # shared primitives: errors, config, auth token state (no HTTP opinions)
├── wazuh-manager/    # Manager REST API client (:55000) — feature-gated resource modules
└── wazuh-cli/        # `wazuhctl` binary — thin consumer of the library
```

## Development workflow

1. Fork the repo and create a branch off `main`:

   ```bash
   git checkout -b feat/my-change
   ```

2. Make your changes. Keep them **minimal and focused** — one logical change
   per PR.

3. Run the checks locally (see [Testing](#testing) and [Style](#style)).

4. Commit with a clear message (see [Commit conventions](#commit-conventions)).

5. Push and open a pull request against `main`.

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>
```

- **type**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `perf`
- **scope** (optional): the crate or area, e.g. `wazuh-cli`, `wazuh-core`,
  `agents`, `tls`
- **summary**: imperative, lowercase, no trailing period

Examples:

```
feat(wazuh-cli): add --ca-cert option to trust a private CA
fix(wazuh-manager): classify TLS failures distinctly from network errors
docs: add contributing guide
```

## Pull request process

- Fill out the [pull request template](.github/pull_request_template.md).
- Reference any related issues (e.g. `Closes #12`).
- Ensure CI (lint, test, build) passes.
- Keep the diff reviewable — split large changes into separate PRs.

## Testing

Run the full test suite:

```bash
cargo test
```

Run a single crate's tests:

```bash
cargo test -p wazuh-manager
```

## Style

- Run `cargo fmt` before committing (CI enforces `cargo fmt --check`).
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any
  warnings (CI enforces this).
- Follow the existing conventions: params structs over positional `Option`
  soup, JSON output by default, logs to stderr, data to stdout.
