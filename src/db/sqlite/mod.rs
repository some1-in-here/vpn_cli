use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Not;
use std::str::FromStr;
use std::path::{PathBuf};

use rusqlite::{Connection, params};
use serde::Deserialize;
use crate::db::Database;
use crate::db::sqlite::migrations::MIGRATIONS;
use crate::error::db::DbError;
use crate::fs::create_parent_dir_all;
use crate::vpn::Peer;
use crate::vpn::wireguard::generate_keypair;

mod migrations;

#[derive(Deserialize)]
pub struct SqliteConfig {
    path: PathBuf,
}

pub struct SqliteDb {
    conn: Connection,
}

impl SqliteDb {
    pub fn open(config: SqliteConfig) -> Result<Self, anyhow::Error> {
        let path = config.path;
        if fs::exists(&path)?.not() {
            create_parent_dir_all(&path)?;
        }

        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let db = SqliteDb { conn };
        db.run_migrations()?;
        Ok(db)
    }

    fn run_migrations(&self) -> Result<(), DbError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _migrations ( \
                name       TEXT PRIMARY KEY, \
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );"
        )?;

        for (name, sql) in MIGRATIONS {
            let count: i32 = self.conn.query_row(
                "SELECT COUNT(*) FROM _migrations WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )?;

            if count == 0 {
                self.conn.execute_batch(sql)?;
                self.conn.execute(
                    "INSERT INTO _migrations (name) VALUES (?1)",
                    params![name],
                )?;
            }
        }

        Ok(())
    }

    // todo: simplify
    fn get_free_ip(&self, subnet: &ipnet::IpNet) -> Result<IpAddr, DbError> {
        let base = match subnet.addr() {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => {
                return Err(DbError::NoAvailableIps);
            }
        };
        let prefix_len = subnet.prefix_len();
        let host_bits = 32 - prefix_len;
        let max_hosts = if host_bits >= 2 {
            (1u32 << host_bits) - 2
        } else {
            0
        };

        let base_octets = base.octets();
        let base_u32 = u32::from_be_bytes(base_octets);
        let network_u32 = base_u32 & (0xFFFFFFFFu32 << host_bits);

        let mut stmt = self.conn.prepare(
            "SELECT ip_address FROM peers ORDER BY ip_address"
        )?;

        let used: Vec<IpAddr> = stmt
            .query_map([], |row| {
                let s: String = row.get(0)?;
                Ok(IpAddr::from_str(&s).ok())
            })?
            .filter_map(|r| r.ok().flatten())
            .collect();

        for host_idx in 1..=max_hosts {
            let raw = network_u32 | host_idx;
            let ip_raw = raw.to_be_bytes();
            let ip = Ipv4Addr::new(ip_raw[0], ip_raw[1], ip_raw[2], ip_raw[3]);

            let candidate = IpAddr::V4(ip);
            if candidate == subnet.addr() {
                continue;
            }
            if !used.contains(&candidate) {
                return Ok(candidate);
            }
        }

        Err(DbError::NoAvailableIps)
    }

    fn user_id(&self, username: &str) -> Result<i64, DbError> {
        let mut stmt = self.conn.prepare("SELECT id FROM users WHERE username = ?1")?;

        stmt.query_row(params![username], |row| row.get(0))
            .map_err(|_| DbError::UserNotFound(username.to_string()))
    }
}

impl Database for SqliteDb {
    fn add_user(&self, username: &str) -> Result<(), DbError> {
        let result = self.conn.execute(
            "INSERT INTO users (username) VALUES (?1)",
            params![username],
        );

        match result {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(DbError::UserAlreadyExists(username.to_string()))
            }
            Err(e) => Err(DbError::Sqlite(e)),
        }
    }

    fn delete_user(&self, username: &str) -> Result<(), DbError> {
        let rows = self.conn.execute(
            "DELETE FROM users WHERE username = ?1",
            params![username],
        )?;

        if rows == 0 {
            return Err(DbError::UserNotFound(username.to_string()));
        }
        Ok(())
    }

    fn enable_user(&self, username: &str) -> Result<(), DbError> {
        let rows = self.conn.execute(
            "UPDATE users SET enabled = 1, updated_at = datetime('now') WHERE username = ?1",
            params![username],
        )?;

        if rows == 0 {
            return Err(DbError::UserNotFound(username.to_string()));
        }
        Ok(())
    }

    fn disable_user(&self, username: &str) -> Result<(), DbError> {
        let rows = self.conn.execute(
            "UPDATE users SET enabled = 0, updated_at = datetime('now') WHERE username = ?1",
            params![username],
        )?;

        if rows == 0 {
            return Err(DbError::UserNotFound(username.to_string()));
        }
        Ok(())
    }

    fn allocate_ip(&self, username: &str, subnet: &ipnet::IpNet) -> Result<Peer, DbError> {
        let uid = self.user_id(username)?;
        let ip = self.get_free_ip(subnet)?;

        let (privkey, pubkey) = generate_keypair();

        self.conn.execute(
            "INSERT INTO peers (user_id, ip_address, public_key, private_key) VALUES (?1, ?2, ?3, ?4)",
            params![uid, ip.to_string(), pubkey, privkey],
        )?;

        Ok(Peer {
            ip_address: ip,
            public_key: pubkey,
            private_key: privkey,
            enabled: true, //todo:
        })
    }

    /// todo: support multiple deallocations( "LIMIT ?2" )
    fn deallocate_ip(&self, username: &str) -> Result<Peer, DbError> {
        let uid = self.user_id(username)?;

        let (ip_address, public_key, private_key, enabled) = self.conn.query_row(
            "DELETE FROM peers \
            WHERE rowid = ( \
                SELECT rowid FROM peers \
                WHERE user_id = ?1 \
                LIMIT 1 \
            ) \
            RETURNING peers.ip_address, peers.public_key, peers.private_key, \
            (SELECT enabled FROM users WHERE users.id = peers.user_id) AS enabled",
            params![uid],
            |row| {
                let ip_address: String = row.get(0)?;
                let public_key: String = row.get(1)?;
                let private_key: String = row.get(2)?;
                let enabled: bool = row.get::<_, i32>(3)? == 1;

                Ok((ip_address, public_key, private_key, enabled))
            }
        )?;


        let ip_address = IpAddr::from_str(&ip_address)
            .map_err(|err| DbError::MalformedValue(ip_address))?;

        Ok(Peer {
            public_key,
            private_key,
            ip_address,
            enabled,
        })
    }

    fn get_users(&self) -> Result<Vec<(String, Vec<IpAddr>, bool)>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT u.username, u.enabled, p.ip_address \
             FROM users u \
             LEFT JOIN peers p ON p.user_id = u.id \
             ORDER BY u.username"
        )?;

        let rows = stmt.query_map([], |row| {
            let username: String = row.get(0)?;
            let enabled: bool = row.get::<_, i32>(1)? != 0;
            let ip_str: Option<String> = row.get(2)?;

            let ip = match ip_str {
                Some(s) => Some(IpAddr::from_str(&s).map_err(|_| {
                    rusqlite::Error::InvalidParameterName(s)
                })?),
                None => None,
            };

            Ok((username, enabled, ip))
        })?;

        let mut users: Vec<(String, Vec<IpAddr>, bool)> = Vec::new();

        for row in rows {
            let (username, enabled, ip) = row?;

            if let Some(pos) = users.iter().position(|(u, _, _)| *u == username) {
                if let Some(ip) = ip {
                    users[pos].1.push(ip);
                }
            } else {
                let ips = match ip {
                    Some(ip) => vec![ip],
                    None => vec![],
                };
                users.push((username, ips, enabled));
            }
        }

        Ok(users)
    }

    fn get_peers(&self) -> Result<Vec<Peer>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT p.ip_address, p.public_key, p.private_key, u.enabled \
             FROM peers p \
             JOIN users u ON u.id = p.user_id \
             WHERE u.enabled = 1 \
             ORDER BY u.username, p.ip_address"
        )?;

        let rows = stmt.query_map([], |row| {
            let ip_address: String = row.get(0)?;
            let public_key: String = row.get(1)?;
            let private_key: String = row.get(2)?;
            let enabled: bool = row.get::<_, i32>(3)? != 0;

            let ip_address = IpAddr::from_str(&ip_address).map_err(|_| {
                rusqlite::Error::InvalidParameterName(ip_address)
            })?;

            Ok(Peer {
                public_key,
                private_key,
                ip_address,
                enabled,
            })
        })?;

        let mut peers = Vec::new();
        for row in rows {
            peers.push(row?);
        }

        Ok(peers)
    }

    fn get_peers_by_username(&self, username: &str) -> Result<Option<Vec<Peer>>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT p.ip_address, p.public_key, p.private_key, u.enabled \
            FROM peers p \
            JOIN users u ON u.id = p.user_id \
            WHERE u.username = ?1 \
            ORDER BY p.ip_address"
        )?;
        let mut rows = stmt
            .query_map(params![username], |row| {
                let ip_address: String = row.get(0)?;
                let public_key: String = row.get(1)?;
                let private_key: String = row.get(2)?;
                let enabled: bool = row.get::<_, i32>(3)? != 0;

                let ip_address = IpAddr::from_str(&ip_address).map_err(|_| {
                    rusqlite::Error::InvalidParameterName(ip_address)
                })?;

                Ok(Peer {
                    public_key,
                    private_key,
                    ip_address,
                    enabled,
                })
            })
            .map_err(|e| DbError::Sqlite(e))?;

        let Some(first) = rows.next() else {
            return Ok(None);
        };

        let mut peers: Vec<Peer> = Vec::with_capacity(1);
        peers.push(first?);
        
        for row in rows {
            peers.push(row?);
        }
        Ok(Some(peers))
    }

    fn get_peer_private_key(&self, username: &str, ip: &IpAddr) -> Result<String, DbError> {
        let uid = self.user_id(username)?;
        let ip_str = ip.to_string();

        let mut stmt = self.conn.prepare(
            "SELECT private_key FROM peers WHERE user_id = ?1 AND ip_address = ?2"
        )?;

        stmt.query_row(params![uid, ip_str], |row| row.get(0))
            .map_err(|_| DbError::UserNotFound(format!("{} / {}", username, ip)))
    }

    fn get_peer_by_ip(&self, ip: &IpAddr) -> Result<Option<Peer>, DbError> {
        let ip_str = ip.to_string();

        let mut stmt = self.conn.prepare(
            "SELECT p.ip_address, p.public_key, p.private_key, u.enabled \
             FROM peers p \
             JOIN users u ON u.id = p.user_id \
             WHERE p.ip_address = ?1"
        )?;

        let mut rows = stmt.query_map(params![ip_str], |row| {
            let ip_address: String = row.get(0)?;
            let public_key: String = row.get(1)?;
            let private_key: String = row.get(2)?;
            let enabled: bool = row.get::<_, i32>(3)? == 1;

            let ip_address = IpAddr::from_str(&ip_address).map_err(|_| {
                rusqlite::Error::InvalidParameterName(ip_address)
            })?;

            Ok(Peer { public_key, private_key, ip_address, enabled })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    fn get_peer_by_public_key(&self, public_key: &str) -> Result<Option<Peer>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT p.ip_address, p.public_key, p.private_key, u.enabled \
             FROM peers p \
             JOIN users u ON u.id = p.user_id \
             WHERE p.public_key = ?1"
        )?;

        let mut rows = stmt.query_map(params![public_key], |row| {
            let ip_address: String = row.get(0)?;
            let public_key: String = row.get(1)?;
            let private_key: String = row.get(2)?;
            let enabled: bool = row.get::<_, i32>(3)? == 1;

            let ip_address = IpAddr::from_str(&ip_address).map_err(|_| {
                rusqlite::Error::InvalidParameterName(ip_address)
            })?;

            Ok(Peer { public_key, private_key, ip_address, enabled })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    fn close(self: Box<Self>) -> Result<(), DbError> {
        let SqliteDb { conn } = *self;
        conn.close().map_err(|(_conn, e)| DbError::Sqlite(e))?;
        Ok(())
    }
}
