use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("could not read config file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("invalid line format (expected 'key = value')")]
    InvalidLine,

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("invalid CIDR address: {0}")]
    InvalidCidr(String),

    #[error("invalid listen port: {0}")]
    InvalidPort(String),

    #[error("empty private key")]
    EmptyPrivateKey,

    #[error("invalid base64 key: {0}")]
    InvalidBase64(String),

    #[error("key must be exactly 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("unsupported VPN type: {0}")]
    UnsupportedVpn(String),

    #[error("VPN type not implemented yet: {0}")]
    NotImplemented(&'static str),
}