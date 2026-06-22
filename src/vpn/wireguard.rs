use std::process::Command;
use crate::error::config::ConfigError;
use crate::vpn::{Peer, VpnController, VpnConfig};
use anyhow::Error;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ipnet::IpNet;
use rand_core::OsRng;
use std::net::IpAddr;
use std::str::FromStr;
use serde::Deserialize;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Wireguard {
    pub config: WireguardConfig,
    iface_name: String,
}
impl Wireguard {
    const NAME: &'static str = "wireguard";

    pub fn build(config: WireguardConfig, iface_name: String) -> Self {
        Wireguard { config, iface_name }
    }
}

impl VpnController for Wireguard {

    fn get_name(&self) -> &'static str {
        Self::NAME
    }

    fn get_config(&self) -> &dyn VpnConfig {
        &self.config
    }

    /// calls `wg set <iface> peer <pubkey> allowed-ips <ip>/32`
    /// to add a peer without restarting the Wireguard service
    fn add_peer(&self, peer: &Peer) -> Result<IpAddr, Error> {
        let output = Command::new("wg")
            .arg("set")
            .arg(&self.iface_name)
            .arg("peer")
            .arg(&peer.public_key)
            .arg("allowed-ips")
            .arg(format!("{}/32", peer.ip_address))
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("wg set failed: {}", stderr);
        }
        Ok(peer.ip_address)
    }

    /// calls `wg set <iface> peer <pubkey> remove`
    /// to remove a peer without restarting the Wireguard service
    fn remove_peer(&self, peer: &Peer) -> Result<(), Error> {
        let output = Command::new("wg")
            .arg("set")
            .arg(&self.iface_name)
            .arg("peer")
            .arg(&peer.public_key)
            .arg("remove")
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("wg set remove failed: {}", stderr);
        }
        Ok(())
    }

}

#[derive(Deserialize)]
pub struct WireguardConfig {
    #[serde(alias = "Address")]
    address: IpNet,
    #[serde(alias = "ListenPort")]
    listen_port: u16,
    #[serde(alias = "PrivateKey")]
    private_key: String,
    #[serde(alias = "PublicKey")]
    public_key: String,
    #[serde(alias = "PostUp")]
    post_up: Option<String>,
    #[serde(alias = "PostDown")]
    post_down: Option<String>,
}

impl WireguardConfig {

    fn address(&self) -> &IpNet {
        &self.address
    }

    fn listen_port(&self) -> u16 {
        self.listen_port
    }

    fn private_key(&self) -> &str {
        &self.private_key
    }

    fn public_key(&self) -> &str {
        &self.public_key
    }

    fn post_up(&self) -> Option<&str> {
        self.post_up.as_deref()
    }

    fn post_down(&self) -> Option<&str> {
        self.post_down.as_deref()
    }
}

impl VpnConfig for WireguardConfig {

    fn get_subnet(&self) -> &IpNet {
        self.address()
    }

    fn render(&self, peers: &[Peer]) -> String {
        let mut out = String::new();

        out.push_str("[Interface]\n");
        out.push_str(&format!("Address = {}\n", self.address));
        out.push_str(&format!("ListenPort = {}\n", self.listen_port));
        out.push_str(&format!("PrivateKey = {}\n", self.private_key));
        if let Some(up) = &self.post_up {
            out.push_str(&format!("PostUp = {}\n", up));
        }
        if let Some(down) = &self.post_down {
            out.push_str(&format!("PostDown = {}\n", down));
        }
        out.push('\n');

        for peer in peers {
            if !peer.enabled {
                continue;
            }
            out.push_str("[Peer]\n");
            out.push_str(&format!("PublicKey = {}\n", peer.public_key));
            out.push_str(&format!("AllowedIPs = {}/32\n", peer.ip_address));
            out.push('\n');
        }

        out
    }

    fn render_client(
        &self,
        peer: &Peer,
        server_endpoint: &IpAddr,
    ) -> String {
        let mut out = String::new();

        out.push_str("[Interface]\n");
        out.push_str(&format!("PrivateKey = {}\n", peer.private_key));
        out.push_str(&format!("Address = {}/32\n", peer.ip_address));
        out.push_str("DNS = 8.8.8.8\n");
        out.push('\n');

        out.push_str("[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", self.public_key));
        out.push_str(&format!("Endpoint = {}:{}\n", server_endpoint, self.listen_port));
        out.push_str("AllowedIPs = 0.0.0.0/0\n");
        out.push_str("PersistentKeepalive = 20\n");

        out
    }
}

pub fn generate_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let priv_b64 = BASE64_STANDARD.encode(secret.to_bytes());
    let pub_b64 = BASE64_STANDARD.encode(public.as_bytes());

    (priv_b64, pub_b64)
}

pub fn derive_public_key(private_key_b64: &str) -> Result<String, ConfigError> {
    let raw = BASE64_STANDARD
        .decode(private_key_b64)
        .map_err(|e| ConfigError::InvalidBase64(e.to_string()))?;

    if raw.len() != 32 {
        return Err(ConfigError::InvalidKeyLength(raw.len()));
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw);

    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);

    Ok(BASE64_STANDARD.encode(public.as_bytes()))
}
