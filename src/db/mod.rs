pub mod sqlite;

use std::net::IpAddr;
use crate::error::db::DbError;
use crate::vpn::Peer;

pub trait Database {
    fn add_user(&self, username: &str) -> Result<(), DbError>;

    fn delete_user(&self, username: &str) -> Result<(), DbError>;

    fn enable_user(&self, username: &str) -> Result<(), DbError>;

    fn disable_user(&self, username: &str) -> Result<(), DbError>;

    fn allocate_ip(&self, username: &str, subnet: &ipnet::IpNet) -> Result<Peer, DbError>;

    fn deallocate_ip(&self, username: &str) -> Result<Peer, DbError>;

    fn get_users(&self) -> Result<Vec<(String, Vec<IpAddr>, bool)>, DbError>;

    fn get_peers(&self) -> Result<Vec<Peer>, DbError>;

    fn get_peers_by_username(&self, username: &str) -> Result<Option<Vec<Peer>>, DbError>;

    fn get_peer_private_key(&self, username: &str, ip: &IpAddr) -> Result<String, DbError>;

    fn get_peer_by_ip(&self, ip: &IpAddr) -> Result<Option<Peer>, DbError>;

    fn get_peer_by_public_key(&self, public_key: &str) -> Result<Option<Peer>, DbError>;

    fn close(self: Box<Self>) -> Result<(), DbError>;
}
