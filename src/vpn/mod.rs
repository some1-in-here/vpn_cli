pub mod openvpn;
pub mod wireguard;

use std::net::IpAddr;
use ipnet::IpNet;

pub struct Peer {
    pub ip_address: IpAddr,
    pub public_key: String,
    pub private_key: String,
    pub enabled: bool,
}


pub trait VpnController {
    fn get_name(&self) -> &'static str;
    fn get_config(&self) -> &dyn VpnConfig;

    /// allocate peer(ip) to a vpn without reloading a VPN service
    fn add_peer(&self, peer: &Peer) -> Result<IpAddr, anyhow::Error>;

    fn remove_peer(&self, peer: &Peer) -> Result<(), anyhow::Error>;
}

pub trait VpnConfig {

    /// Isolated, virtual Ip range assigned to the VPN tunnel interface, i.e. 10.0.1.0/24
    fn get_subnet(&self) -> &IpNet;

    fn render(&self, peers: &[Peer]) -> String;

    fn render_client(&self, peer: &Peer, server_endpoint: &IpAddr,) -> String;
}

