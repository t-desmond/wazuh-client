# wazuh-client

Rust workspace for talking to [Wazuh](https://wazuh.com) — a Manager REST API
client library, a CLI built on top of it, and shared primitives. Designed for
automated pipelines from day one.

```
wazuh-client/
├── crates/
│   ├── wazuh-core/       # shared primitives: errors, config, auth token state (no HTTP opinions)
│   ├── wazuh-manager/    # Manager REST API client (:55000) — feature-gated resource modules
│   ├── wazuh-indexer/    # Indexer/OpenSearch API (:9200) — not yet implemented
│   └── wazuh-cli/        # `wazuhctl` binary — thin consumer of the library
```

## Crates

| Crate | Purpose |
|---|---|
| `wazuh-core` | The genuinely shared pieces — `WazuhError`, `ManagerConfig`, auth token state. Deliberately has **no HTTP client opinions**, so `wazuh-manager` and `wazuh-indexer` don't depend on each other but don't duplicate the JWT dance either. |
| `wazuh-manager` | Typed client for the Manager REST API. A single request choke point composes rate limiting, proactive token refresh, and a single reactive retry on 401. Resource modules (`agents`, ...) are feature-gated so you only compile in what you use. |
| `wazuh-cli` | The `wazuhctl` binary. Thin: arg parsing, output formatting, exit codes. All API logic lives in the library. |

## Install / build

```bash
cargo build --release
# binary at target/release/wazuhctl
```

## CLI: `wazuhctl`

Pipeline-friendly: **JSON output by default**, meaningful **exit codes**, auth
via **env vars** (no prompts), logs to **stderr** only.

### Authentication

Credentials come from flags or environment variables (flags win):

```bash
export WAZUH_API_HOST=wazuh.example.com
export WAZUH_API_PORT=55000
export WAZUH_API_USER=wazuh
export WAZUH_API_PASSWORD='...'
```

### Commands

```bash
# Check connectivity + report server version
wazuhctl ping

# List agents (JSON by default)
wazuhctl agents list
wazuhctl agents list --status active --group linux
wazuhctl agents list --all          # paginate through every agent

# Get a single agent
wazuhctl agents get 001

# Human-readable tables
wazuhctl agents list --output table
```

### Exit codes

Pipelines branch on exit codes, not stderr text:

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | partial failure (some items failed) |
| `2` | authentication failure |
| `3` | API error |
| `4` | network error / timeout |
| `5` | resource not found |
| `6` | configuration error |
| `7` | response decode error |

### Piping into `jq`

```bash
wazuhctl agents list --status active | jq -r '.[].name'
```

## Library usage

```rust,no_run
use wazuh_core::ManagerConfig;
use wazuh_manager::agents::ListAgentsParams;
use wazuh_manager::ManagerClient;

#[tokio::main]
async fn main() -> Result<(), wazuh_core::WazuhError> {
    let config = ManagerConfig {
        host: "wazuh.example.com".into(),
        username: "wazuh-wui".into(),
        password: "secret".into(),
        ..Default::default()
    };
    let client = ManagerClient::new(config)?;

    let agents = client.list_agents(&ListAgentsParams::default()).await?;
    for agent in agents.affected_items {
        println!("{} {}", agent.id, agent.name);
    }
    Ok(())
}
```

## Design notes

The design is informed by surveying existing Wazuh clients across languages
(Go, Python, TypeScript, Rust) and their issue trackers. Highlights:

- **Single request choke point** — rate limit → proactive token refresh → send
  → single 401 retry, all in one function so typed methods can't bypass them.
- **HTTP 200 ≠ success** — Wazuh signals failures through the response
  envelope's `error` field (`0` complete, `1` failed, `2` partial). The client
  surfaces partial failures as `WazuhError::Partial` carrying the failed items.
- **Safe by default** — TLS verification is **on**; no fallback to default
  credentials.
- **Client-side rate limiting** — sliding window at 12 req / 3s (~240 req/min),
  safely under Wazuh's default server limit of 300 req/min.
- **Proactive + reactive token refresh** — refresh before the TTL (default 840s,
  a margin under Wazuh's 900s server default), and re-auth once on 401.
- **Params structs, not positional `Option` soup** — avoids the
  `get_rules(Some(5), None, None, None, None)` anti-pattern.
- **Lenient deserialization** — Wazuh returns some fields as either strings or
  numbers across versions (e.g. `revision`); handled with custom deserializers.

### Feature flags

`wazuh-manager` gates resource modules so you only compile in what you need:

```toml
[features]
default = ["agents"]
agents = []
rules = []
cluster = []
rbac = []
full = ["agents", "rules", "cluster", "rbac"]
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full, prioritized plan (phases, effort,
and the research lessons that drive it). Short version:

- [x] `wazuh-core` (errors, config, auth)
- [x] `wazuh-manager` — agents (list / get / stream), `ping`
- [ ] `wazuh-manager` — rules, cluster, RBAC, tasks modules
- [ ] `wazuh-indexer` — alerts & vulnerabilities (newest-first sort + `search_after`
      pagination baked in from day one)
- [ ] JWT `exp` decoding instead of a configured TTL

## License

MIT OR Apache-2.0
