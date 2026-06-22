use std::net::IpAddr;
use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, default_value = "./vpn_cli.json")]
    pub app_config_path: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    AddUser {
        // #[arg(short, long)]
        username: String,
    },
    DeleteUser {
        // #[arg(short, long)]
        username: String,
    },
    EnableUser {
        // #[arg(short, long)]
        username: String,
    },
    DisableUser {
        // #[arg(short, long)]
        username: String,
    },
    AllocateIp {
        // #[arg(short, long)]
        username: String,
        /// Path to place the client's configuration. If it's omitted - it'll be shown in the std output.
        #[arg(short, long)]
        output_path: Option<PathBuf>
    },
    DeallocateIp {
        // #[arg(short, long)]
        username: String,
    },
    ListUsers,

    GenerateConfigExample {
        #[arg(default_value = "./vpn_cli.json")]
        output_path: PathBuf,
    },

    #[command(subcommand)]
    ExportPeer (ExportPeerConfig),

    ExportUser (ExportUserConfig),
}

#[derive(Subcommand)]
pub enum ExportPeerConfig {
    ByIp {
        ip: IpAddr,
    },
    ByPublicKey {
        public_key: String,
    }
}

#[derive(Parser)]
pub struct ExportUserConfig {
    // #[arg(short, long)]
    pub nickname: String,

    #[arg(short, long)]
    pub output_dir: PathBuf,
}
