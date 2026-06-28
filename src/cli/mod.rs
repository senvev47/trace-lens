use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "trace-lens",
    version,
    about = "Blue team tracing, attribution, Ring0 inspection, and EDR integration"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
        #[arg(long, default_value_t = 60)]
        ring0_interval_seconds: u64,
    },
    InitDb {
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
    },
    Status {
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
    },
    Events {
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    Ring0 {
        #[command(subcommand)]
        command: Ring0Command,
    },
    Proc {
        pid: i64,
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
        #[arg(long, default_value_t = false)]
        descendants: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Incident {
        pid: i64,
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Net {
        target: String,
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    File {
        path: String,
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long, default_value_t = false)]
        chain: bool,
    },
    Hunt {
        #[arg(default_value = "ring0")]
        scope: String,
    },
    Export {
        #[arg(default_value = "report")]
        format: String,
        #[arg(long, default_value_t = 4242)]
        pid: i64,
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
        #[arg(long, default_value = "runtime/exports")]
        output_dir: PathBuf,
    },
    Replay {
        incident: String,
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
    },
    Edr {
        #[arg(default_value = "list")]
        action: String,
    },
    Canary {
        #[command(subcommand)]
        command: CanaryCommand,
    },
    Tracee {
        #[command(subcommand)]
        command: TraceeCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum TraceeCommand {
    Plan,
    Ingest {
        #[arg(long)]
        input: String,
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum Ring0Command {
    Check {
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
    },
    Findings {
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
pub enum CanaryCommand {
    Setup,
    Serve,
    Check {
        #[arg(long, default_value = "db/trace-lens.db")]
        db_path: PathBuf,
    },
}
