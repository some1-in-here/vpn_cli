use anyhow::{Context, Error};
use clap::Parser;
use serde_json::json;
use std::fs;
use std::net::IpAddr;
use vpn_cli::cli::{Cli, Command, ExportPeerConfig};
use vpn_cli::config::{AppConfig, DbConfig, VpnInfo, VpnInfoBase};
use vpn_cli::db::Database;
use vpn_cli::db::sqlite::SqliteDb;
use vpn_cli::error::db::DbError;
use vpn_cli::fs::create_parent_dir_all;
use vpn_cli::vpn::wireguard::{Wireguard};
use vpn_cli::vpn::{VpnController};
use vpn_cli::vpn::openvpn::OpenVpn;

fn run() -> Result<(), Error> {
    let args = Cli::parse();
    let config = AppConfig::load(&args.app_config_path)?;

    let database: Box<dyn Database> = match config.database {
        DbConfig::Sqlite(config) => {
            let sqlite = SqliteDb::open(config)?;
            Box::new(sqlite)
        },
    };

    let (vpn_controller, vpn_base_config): (Box<dyn VpnController>, VpnInfoBase) = match config.vpn {
        VpnInfo::Wireguard { config, base } => {
            let iface_name = base.config_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("wg0")
                .to_string();
            let wg_controller = Wireguard::build(config, iface_name);
            (Box::new(wg_controller), base)
        }
        VpnInfo::OpenVpn { config, base } => {
            let openvpn_controller = OpenVpn::build(config);
            (Box::new(openvpn_controller), base)
        }
    };

    let needs_sync: bool = match dispatch_commands(
        args.command,
        &vpn_controller,
        &database,
        &config.server.public_ip,
    ) {
        Ok(needs_sync) => needs_sync,
        Err(err) => {
            close_db(database)?;
            return Err(err);
        }
    };

    if needs_sync {
        let config_path = vpn_base_config.config_path;
        create_parent_dir_all(&config_path)?;
        let peers = database.get_peers()?;
        let content = vpn_controller.get_config().render(&peers);
        fs::write(&config_path, &content)
            .with_context(|| format!("failed to write config to {:?}", config_path))?;
        println!("config updated: {:?}", config_path);
    }

    close_db(database)?;
    Ok(())
}

fn close_db(database: Box<dyn Database>) -> Result<(), Error> {
    database.close().with_context(|| "Failed to close database")
}

fn dispatch_commands(
    cmd: Command,
    vpn_controller: &Box<dyn VpnController>,
    database: &Box<dyn Database>,
    endpoint: &IpAddr,
) -> Result<bool, Error> {
    let vpn_config = vpn_controller.get_config();
    let mut needs_sync = false;

    match cmd {
        Command::AddUser { username } => {
            database.add_user(&username)?;
            println!("user '{}' added", username);
        }
        Command::DeleteUser { username } => {
            let Some(peers) = database.get_peers_by_username(&username)? else {
                let err = Error::from(DbError::UserNotFound(username));
                return Err(err);
            };

            database.delete_user(&username)?;
            for peer in peers {
                vpn_controller.remove_peer(&peer)?;
            }
            println!("user '{}' deleted", username);
            needs_sync = true;
        }
        Command::EnableUser { username } => {
            let Some(peers) = database.get_peers_by_username(&username)? else {
                let err = Error::from(DbError::UserNotFound(username));
                return Err(err);
            };

            database.enable_user(&username)?;
            for peer in peers {
                vpn_controller.add_peer(&peer)?;
            }
            // todo: убедиться, что во время выключения, ip не может быть занят.
            println!("user '{}' enabled", username);
            needs_sync = true;
        }
        Command::DisableUser { username } => {
            let Some(peers) = database.get_peers_by_username(&username)? else {
                let err = Error::from(DbError::UserNotFound(username));
                return Err(err);
            };

            database.disable_user(&username)?;
            for peer in peers {
                vpn_controller.remove_peer(&peer)?;
            }
            println!("user '{}' disabled", username);
            needs_sync = true;
        }
        Command::AllocateIp { username, output_path } => {
            let peer = database.allocate_ip(&username, vpn_config.get_subnet())?;
            vpn_controller.add_peer(&peer)?;

            println!("allocated {} to '{}'\n", peer.ip_address, username);

            let client = vpn_config.render_client(&peer, endpoint);
            println!("--- client config ---");
            println!("{}", client);
            println!("--- ------------- ---");

            match output_path {
                Some(output_path) => {
                    create_parent_dir_all(&output_path)?;
                    match fs::write(&output_path, client) {
                        Ok(_) => println!("Config was written to {:?}", output_path),
                        Err(err) => println!("Failed to write client config to file: {:?}", err)
                    };
                }
                _ => {}
            }

            needs_sync = true;
        }
        Command::DeallocateIp { username } => {
            let peer = database.deallocate_ip(&username)?;
            vpn_controller.remove_peer(&peer)?;

            println!("deallocated '{}' from '{}'", peer.ip_address, username);
            needs_sync = true;
        }
        Command::ListUsers => {
            let users = database.get_users()?;
            if users.is_empty() {
                println!("no users found");
            } else {
                println!("{:<20} {:<40} {}", "username", "ips", "status");
                println!("{:-<20} {:-<40} {:-<8}", "", "", "");
                for (username, ips, enabled) in &users {
                    let ips = if ips.is_empty() {
                        "-".to_string()
                    } else {
                        ips.iter()
                            .map(|ip| ip.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    let status = if *enabled { "enabled" } else { "disabled" };
                    println!("{:<20} {:<40} {}", username, ips, status);
                }
            }
        }
        Command::GenerateConfigExample {output_path} => {
            let example = json!({
                "server": {
                    "public_ip": "12.13.14.15"
                },
                "database": {
                    "kind": "sqlite",
                    "path": "./vpn_cli.db"
                },
                "vpn": {
                    "kind": "wireguard",
                    "config_path": "./wg0.conf",
                    "config": {
                        "PrivateKey": "VhHidCA3lfUJ+/0kUoET4wTVizvkQA7hAojQtcP7nS0=",
                        "PublicKey": "Hob3kPv0RnSBM6knWUlqkxCykUJcnvflX9QVkpJAJEw=",
                        "Address": "10.0.0.1/24",
                        "ListenPort": "51820",
                        "PostUp": "iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
                        "PostDown": "iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"
                    }
                }
            }).to_string();
            create_parent_dir_all(&output_path)?;
            fs::write(output_path, example)?;
            println!("Check ./vpn_cli.json and modify it with your actual data");
        }
        Command::ExportPeer(export_config) => {
            let peer = match export_config {
                ExportPeerConfig::ByIp { ip } => database.get_peer_by_ip(&ip)?
                    .ok_or_else(|| anyhow::anyhow!("peer with IP {} not found", ip))?,
                ExportPeerConfig::ByPublicKey { public_key } => database.get_peer_by_public_key(&public_key)?
                    .ok_or_else(|| anyhow::anyhow!("peer with public key {} not found", public_key))?,
            };
            let client = vpn_config.render_client(&peer, endpoint);
            println!("--- client config ---");
            println!("{}", client);
            println!("--- ------------- ---");
        }
        Command::ExportUser(config) => {
            let Some(peers) = database.get_peers_by_username(&config.nickname)? else {
                return Err(Error::from(DbError::UserNotFound(config.nickname)));
            };

            fs::create_dir_all(&config.output_dir)
                .with_context(|| format!("failed to create output dir {:?}", config.output_dir))?;

            for peer in peers {
                let client = vpn_config.render_client(&peer, endpoint);
                let filename = config.output_dir.join(format!("{}_{}.conf", config.nickname, peer.ip_address));
                fs::write(&filename, &client)
                    .with_context(|| format!("failed to write config to {:?}", filename))?;
                println!("exported {} -> {:?}", peer.ip_address, filename);
            }
        }
    }

    Ok(needs_sync)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:?}");
        std::process::exit(1);
    }
}