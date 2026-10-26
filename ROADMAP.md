# Roadmap

This is the living plan for the `wazuh-client` workspace. It's informed by a
survey of existing Wazuh clients across languages (Go, Python, TypeScript,
Rust) and their issue trackers — the "what went wrong elsewhere" section below
records the concrete lessons that drive the priorities.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

## Guiding principles

These are non-negotiable and shape every item below:

1. **Data on stdout, logs on stderr — always.** Debug/verbose output must never
   mix into stdout, or `wazuhctl ... | jq` silently corrupts.
2. **JSON by default, human tables behind a flag.** Pipelines are first-class.
3. **Meaningful exit codes.** Pipelines branch on exit codes, not stderr text.
4. **Safe by default.** TLS verification on, no default-credential fallback.
5. **Single request choke point.** Rate limit → proactive token refresh → send
   → single 401 retry, in one function typed methods can't bypass.
6. **HTTP 200 ≠ success.** Wazuh signals failure via the envelope's `error`
   field (`0`/`1`/`2`); partial failures surface as `WazuhError::Partial`.
7. **Params structs, not positional `Option` soup.**
8. **Feature-gate resource modules** so users only compile in what they use.

## Current state

- [x] `wazuh-core` — errors, config, auth token state (no HTTP opinions)
- [x] `wazuh-manager` — agents (list / get / stream), `ping`, envelope/bulk types
- [x] `wazuh-cli` → `wazuhctl` binary — JSON default, exit codes, env auth
- [x] Unit tests for envelope/error parsing, config, query building

## Phase 1 — Foundation hardening (small, high value)

| Item | Priority | Effort | Status |
|---|---|---|---|
| **Token injection** — accept a pre-issued JWT via `--token` / `WAZUH_API_TOKEN` instead of always doing the password dance. Seeds `AuthToken` state directly. Unblocks IdP/vault/CI-secret use. | P0 | S | [ ] |
| **Rich `-v`** — per-request detail on **stderr**: method, URL, status, timing, token-refresh events. | P0 | S | [ ] |
| **Raw `request()` escape hatch** — expose the low-level request on `ManagerClient` so users can hit endpoints we haven't typed yet (wazuh-api-kit's pattern for shipping small without blocking anyone). | P0 | S | [ ] |
| **JWT `exp` decoding** — read the token's actual expiry instead of trusting a configured TTL, killing the "mismatched TTL" warning class. | P2 | S | [ ] |

## Phase 2 — CLI ergonomics

| Item | Priority | Effort | Status |
|---|---|---|---|
| **Colored output** — `comfy-table` + ANSI, **TTY-gated** (auto-detect, `--color auto\|always\|never`), respect `NO_COLOR`. JSON stays uncolored. | P1 | M | [ ] |
| **Shell completions** — `wazuhctl completion bash\|zsh\|fish` (clap generates for free). | P1 | S | [ ] |
| **`--output jsonl`** — one JSON object per line; ideal for streaming logs/alerts and `while read` loops. | P1 | S | [ ] |
| **`--retries` + 429 backoff** — retry/backoff on transient failures and server `429` (we already rate-limit client-side; this handles the server side). | P1 | M | [ ] |
| **Config file** — `~/.config/wazuhctl/config.toml`; precedence `flags > env > config file > defaults`. | P1 | M | [ ] |
| **`--select` field projection** — expose Wazuh's `select` param so pipelines pull only needed fields. | P2 | S | [ ] |
| **Proxy support** — expose `--proxy` / honor `HTTPS_PROXY`. | P2 | S | [ ] |

## Phase 3 — Auth & integrations

| Item | Priority | Effort | Status |
|---|---|---|---|
| **OAuth2 client-credentials flow** — `--auth oauth2` mode for deployments where Wazuh trusts an IdP. Feature-gated; conditional on infra. | P2 | M | [ ] |
| **mTLS / client certs** — `--client-cert` / `--client-key` for deployments that require it. | P2 | M | [ ] |
| **Secret-manager-backed credentials** — pull from Vault / AWS Secrets Manager. Kept **out of core**; pipelines inject via env. | P3 | M | [ ] |

> Note: true SSO (SAML/OIDC) is a **server-side Wazuh config** concern, not a
> client one. The client's job is to accept whatever token the deployment
> produces — which is what token injection (Phase 1) enables.

## Phase 4 — Library expansion (Manager modules)

Feature-gated modules, mirroring the API surface. Each follows the same
pattern as `agents` (params struct, typed models, stream where paginated).

| Item | Priority | Effort | Status |
|---|---|---|---|
| `rules` | P2 | M | [ ] |
| `cluster` | P2 | M | [ ] |
| `rbac` | P2 | M | [ ] |
| `tasks` | P2 | M | [ ] |
| **Version guards** — tag endpoints with min/max version, checked against the cached server version (from `ping`/`api_info`); warn/fail at call time. Protects against version-drift bugs. | P2 | M | [ ] |

## Phase 5 — Indexer

Alerts and vulnerabilities live in the **Indexer** (OpenSearch, :9200), not the
Manager REST API. This is a separate crate with its own auth surface and
transitive deps.

| Item | Priority | Effort | Status |
|---|---|---|---|
| `wazuh-indexer` crate skeleton — basic auth, `_search` | P2 | L | [ ] |
| **Newest-first sort baked in from day one** (the exact bug in `wazuh-client-rs` #4) | P2 | S | [ ] |
| **`search_after` pagination** (the exact bug in `wazuh-client-rs` #3 — hardcoded 100 cap, no paging) | P2 | M | [ ] |
| Typed `Alert` / `Vulnerability` models | P2 | M | [ ] |

## Out of scope (explicitly not doing)

- **Interactive REPL** — the existing `wazuh-cli` project does this; it's the
  opposite of pipeline-oriented.
- **`--dry-run`** — only meaningful once mutating commands exist (restart
  agents, active response); design for it then, not now.
- **HTTP-client abstraction trait** — none of the surveyed projects do it; it's
  speculative complexity.

## What went wrong elsewhere (drives the priorities)

From the research into existing clients and their issue trackers:

- **`wazuh-client-rs` #4** — indexer returned alerts from June 2025 instead of
  recent ones: the query had **no sort clause** (oldest-first). → Phase 5.
- **`wazuh-client-rs` #3** — results capped at 100: hardcoded `limit.unwrap_or(100)`
  and **no pagination helper anywhere**. → Phase 5.
- **`wazuh-client-rs` README** — taught `VERIFY_SSL=false` and default
  credentials. → We default TLS on, no credential fallback (principle 4).
- **`wazuh-client-rs`** — positional `Option` arg soup, hand-rolled unencoded
  query strings, `Ok(None)` swallowing errors. → Principles 7, 5, 6.
- **`wazuh-api-kit`** — trusts a configured TTL instead of reading JWT `exp`
  (produces "mismatched TTL" warnings). → Phase 1 JWT `exp` item.
- **Centreon plugin** — broke when Wazuh required tokens; template drift.
  → Version guards (Phase 4).

## Decision log

- **Binary name `wazuhctl`** — distinct from the product and the endpoint
  "Wazuh agent" daemon; avoids ambiguity. Package stays `wazuh-cli`.
- **Library crates keep `wazuh-*` names** — they're namespaced libraries;
  only the CLI binary needed a distinct name.
- **`wazuh-core` has no HTTP opinions** — so `wazuh-manager` and
  `wazuh-indexer` don't depend on each other but don't duplicate the JWT dance.
