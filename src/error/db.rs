use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("user '{0}' already exists")]
    UserAlreadyExists(String),

    #[error("user '{0}' not found")]
    UserNotFound(String),

    #[error("no available IP addresses in subnet")]
    NoAvailableIps,

    #[error("Extracted value {0} is malformed")]
    MalformedValue(String),
}
