pub const MIGRATIONS: &[(&str, &str)] = &[
    ("001_create_users", include_str!("001_create_users.sql")),
    ("002_create_peers", include_str!("002_create_peers.sql")),
];
