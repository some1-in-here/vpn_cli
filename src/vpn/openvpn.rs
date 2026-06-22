use std::net::IpAddr;
use anyhow::Error;
use ipnet::IpNet;
use serde::Deserialize;
use crate::error::config::ConfigError;
use crate::vpn::{Peer, VpnController, VpnConfig};

pub struct OpenVpn {
    config: OpenVpnConfig,
}
impl OpenVpn {
    const NAME: &'static str = "openvpn";
    
    pub fn build(config: OpenVpnConfig) -> Self {
        todo!()
    }
}

impl VpnController for OpenVpn {

    fn get_name(&self) -> &'static str {
        Self::NAME
    }

    fn get_config(&self) -> &dyn VpnConfig {
        todo!()
    }

    /// todo: abstract peer to support openvpn
    fn add_peer(&self, peer: &Peer) -> Result<IpAddr, Error> {
        todo!()
    }

    fn remove_peer(&self, peer: &Peer) -> Result<(), Error> {
        todo!()
    }
}

#[derive(Deserialize)]
pub struct OpenVpnConfig {
    address: IpNet,
    listen_port: u16,
    private_key: String,
    public_key: String,
    dns: Option<String>,
}

impl OpenVpnConfig {
    pub fn load() -> Result<Self, ConfigError> {
        todo!()
    }
}

impl VpnConfig for OpenVpnConfig {

    fn get_subnet(&self) -> &IpNet {
        todo!()
    }

    fn render(&self, _peers: &[Peer]) -> String {
        String::new()
    }

    fn render_client(&self, peer: &Peer, server_endpoint: &IpAddr) -> String {
        todo!()
    }
}
