use std::net::IpAddr;
use std::path::PathBuf;
use serde::Deserialize;
use crate::db::sqlite::SqliteConfig;
use crate::vpn::openvpn::OpenVpnConfig;
use crate::vpn::wireguard::WireguardConfig;

#[derive(Deserialize)]
pub struct ServerConfig {
    pub public_ip: IpAddr,
}

#[derive(Deserialize)]
#[serde(tag = "kind")]
pub enum DbConfig {
    #[serde(alias = "sqlite")]
    Sqlite(SqliteConfig),
}

#[derive(Deserialize)]
#[serde(tag = "kind")]
pub enum VpnInfo {
    #[serde(alias = "wireguard")]
    Wireguard {
        #[serde(flatten)]
        base: VpnInfoBase,
        config: WireguardConfig,
    },
    #[serde(alias = "openvpn")]
    OpenVpn {
        #[serde(flatten)]
        base: VpnInfoBase,
        config: OpenVpnConfig,
    },
}


#[derive(Deserialize)]
pub struct VpnInfoBase {
    pub config_path: PathBuf,
}


#[derive(Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DbConfig,
    pub vpn: VpnInfo,
}

impl AppConfig {
    pub fn load(app_config_path: &PathBuf) -> Result<AppConfig, anyhow::Error> {
        let content = std::fs::read_to_string(app_config_path)?;
        serde_json::from_str(&content).map_err(|e| anyhow::anyhow!("{}", e))
    }
}