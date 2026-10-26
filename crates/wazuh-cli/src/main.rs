//! Pipeline-friendly CLI for the Wazuh Manager API.
//!
//! Design rules (from the research):
//! - **JSON output by default** so pipelines can pipe into `jq`; human tables
//!   behind `--output table`.
//! - **Meaningful exit codes** — pipelines branch on exit codes, not stderr.
//! - **Non-interactive auth** via env vars / flags; no password prompt as the
//!   primary path.
//! - **Logs to stderr, data to stdout** — always.
//!
//! Exit codes:
//! - `0` success
//! - `1` partial failure (some items failed)
//! - `2` authentication failure
//! - `3` API error
//! - `4` network error / timeout
//! - `5` resource not found
//! - `6` configuration error
//! - `7` response decode error

use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};
use wazuh_core::{ManagerConfig, WazuhError};
use wazuh_manager::agents::{Agent, ListAgentsParams};
use wazuh_manager::{ApiInfo, ManagerClient};

#[derive(Parser)]
#[command(name = "wazuhctl", version, about, long_about = None)]
struct Cli {
    /// Wazuh manager host (optionally with https:// scheme)
    #[arg(long, env = "WAZUH_API_HOST", value_name = "HOST")]
    host: Option<String>,

    #[arg(long, env = "WAZUH_API_PORT", default_value_t = 55000, value_name = "PORT")]
    port: u16,

    #[arg(long, env = "WAZUH_API_USER", value_name = "USER")]
    user: Option<String>,

    #[arg(long, env = "WAZUH_API_PASSWORD", value_name = "PASSWORD", hide_env_values = true)]
    password: Option<String>,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 30, value_name = "SECONDS")]
    timeout: u64,

    /// Skip TLS certificate verification (insecure; avoid in production)
    #[arg(long)]
    insecure: bool,

    /// Output format (json is the default so pipelines can pipe into jq)
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    output: OutputFormat,

    /// Enable debug logging on stderr
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum OutputFormat {
    Json,
    Table,
}

#[derive(Subcommand)]
enum Command {
    /// Agent operations
    Agents {
        #[command(subcommand)]
        command: AgentsCommand,
    },
    /// Check connectivity to the manager and report server version
    Ping,
}

#[derive(Subcommand)]
enum AgentsCommand {
    /// List agents
    List {
        #[arg(long, value_name = "STATUS")]
        status: Option<String>,
        #[arg(long, value_name = "GROUP")]
        group: Option<String>,
        #[arg(long, value_name = "TEXT")]
        search: Option<String>,
        /// Fetch all agents, paginating automatically
        #[arg(long)]
        all: bool,
        /// Page size (max 100000; default 500)
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
    },
    /// Get a single agent by id
    Get {
        #[arg(value_name = "ID")]
        id: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match run(&cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            if matches!(err, WazuhError::Network { .. } | WazuhError::Timeout) {
                eprintln!(
                    "hint: could not reach the manager at {}:{}. Check that the host is \
                     reachable (firewall/VPN) and the port is correct.",
                    cli.host.as_deref().unwrap_or("<host>"),
                    cli.port
                );
            }
            ExitCode::from(exit_code(&err))
        }
    }
}

fn init_tracing(verbose: bool) {
    use tracing_subscriber::EnvFilter;
    let filter = if verbose { "debug" } else { "off" };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("off")))
        .with_writer(std::io::stderr)
        .try_init();
}

fn exit_code(err: &WazuhError) -> u8 {
    match err {
        WazuhError::Partial(_) => 1,
        WazuhError::Auth { .. } | WazuhError::Unauthorized => 2,
        WazuhError::Api { .. } | WazuhError::Http { .. } => 3,
        WazuhError::Network { .. } | WazuhError::Timeout => 4,
        WazuhError::NotFound { .. } => 5,
        WazuhError::Config(_) => 6,
        WazuhError::Json(_) => 7,
    }
}

async fn run(cli: &Cli) -> Result<(), WazuhError> {
    let config = ManagerConfig {
        host: cli
            .host
            .clone()
            .ok_or_else(|| WazuhError::Config("missing --host (or WAZUH_API_HOST)".into()))?,
        port: cli.port,
        username: cli
            .user
            .clone()
            .ok_or_else(|| WazuhError::Config("missing --user (or WAZUH_API_USER)".into()))?,
        password: cli
            .password
            .clone()
            .ok_or_else(|| WazuhError::Config("missing --password (or WAZUH_API_PASSWORD)".into()))?,
        verify_tls: !cli.insecure,
        timeout: Duration::from_secs(cli.timeout),
        ..ManagerConfig::default()
    };

    let client = ManagerClient::new(config)?;

    match &cli.command {
        Command::Agents { command } => match command {
            AgentsCommand::List {
                status,
                group,
                search,
                all,
                limit,
            } => {
                let params = ListAgentsParams {
                    status: status.clone(),
                    group: group.clone(),
                    search: search.clone(),
                    limit: *limit,
                    ..Default::default()
                };
                if *all {
                    let mut stream = client.stream_agents(params);
                    let mut agents = Vec::new();
                    while let Some(agent) = stream.next().await? {
                        agents.push(agent);
                    }
                    print_agents(cli.output, &agents);
                } else {
                    let bulk = client.list_agents(&params).await?;
                    print_agents(cli.output, &bulk.affected_items);
                }
            }
            AgentsCommand::Get { id } => {
                let agent = client.get_agent(id).await?;
                print_agent(cli.output, &agent);
            }
        },
        Command::Ping => {
            let start = Instant::now();
            let info = client.api_info().await?;
            let latency_ms = start.elapsed().as_millis() as u64;
            print_ping(cli.output, &info, latency_ms);
        }
    }

    Ok(())
}

fn print_ping(format: OutputFormat, info: &ApiInfo, latency_ms: u64) {
    match format {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "reachable": true,
                "api_version": info.api_version,
                "hostname": info.hostname,
                "type": info.r#type,
                "latency_ms": latency_ms,
            });
            println!("{}", serde_json::to_string_pretty(&out).expect("ping serializes"));
        }
        OutputFormat::Table => {
            println!("Reachable:   yes");
            println!("API version: {}", info.api_version.as_deref().unwrap_or("-"));
            println!("Hostname:    {}", info.hostname.as_deref().unwrap_or("-"));
            println!("Type:        {}", info.r#type.as_deref().unwrap_or("-"));
            println!("Latency:     {latency_ms} ms");
        }
    }
}

fn print_agents(format: OutputFormat, agents: &[Agent]) {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(agents).expect("agents serialize"));
        }
        OutputFormat::Table => {
            println!("{:<5} {:<28} {:<16} {:<15} {}", "ID", "NAME", "STATUS", "IP", "OS");
            for a in agents {
                println!(
                    "{:<5} {:<28} {:<16} {:<15} {}",
                    a.id,
                    truncate(&a.name, 28),
                    a.status.as_deref().unwrap_or("-"),
                    a.ip.as_deref().unwrap_or("-"),
                    a.os.as_ref()
                        .and_then(|o| o.name.as_deref())
                        .unwrap_or("-"),
                );
            }
        }
    }
}

fn print_agent(format: OutputFormat, agent: &Agent) {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(agent).expect("agent serializes"));
        }
        OutputFormat::Table => print_agents(format, std::slice::from_ref(agent)),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
