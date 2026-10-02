use thiserror::Error;

/// Everything `vmkit` can fail with.
#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{binary} not found: set {env} or put it on PATH")]
    BinaryNotFound { binary: &'static str, env: &'static str },
    #[error("{binary} {found} is older than the minimum supported {min}")]
    VersionTooOld {
        binary: &'static str,
        found: String,
        min: String,
    },
    #[error("cannot read the version of {binary} from {output:?}")]
    VersionUnknown { binary: &'static str, output: String },
    #[error("{backend} API {method} {path} failed with HTTP {status}: {body}")]
    Api {
        backend: &'static str,
        method: &'static str,
        path: String,
        status: u16,
        body: String,
    },
    #[error("malformed API response: {0}")]
    Http(String),
    #[error("{requested} virtio devices requested but only {available} are available")]
    TooManyDevices { requested: u32, available: u32 },
    #[error("invalid VM spec: {0}")]
    InvalidSpec(String),
    #[error("{0} is not supported yet")]
    Unsupported(&'static str),
    #[error("the VMM exited before it was ready ({0})")]
    EarlyExit(String),
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
