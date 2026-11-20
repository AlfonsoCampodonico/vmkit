use thiserror::Error;

/// Everything `vmkit` can fail with.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{binary} not found: set {env} or put it on PATH")]
    BinaryNotFound { binary: &'static str, env: &'static str },
    #[error("{0} not found on PATH or in /usr/sbin, /sbin, /usr/bin or /bin")]
    ToolNotFound(&'static str),
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
    #[error("missing prerequisite: {0}")]
    Prerequisite(String),
    #[error("{0} is not supported yet")]
    Unsupported(&'static str),
    #[error("the VMM exited before it was ready ({0})")]
    EarlyExit(String),
    #[error("snapshot: {0}")]
    Snapshot(String),
    #[error("timed out waiting for {0}")]
    Timeout(String),
    /// `Vm::set_egress` on a VM whose egress vmkit does not police: no NIC, or an attached
    /// tap ([`crate::TapAttach`]), whose caller owns the policy.
    #[error("the VM's egress cannot be set: {0}")]
    EgressUnavailable(&'static str),
    /// `Vm::set_egress` could not switch the policy (the VM ended, or `nft` failed); the
    /// policy in force is unchanged, since the switch is one transaction.
    #[error("setting the VM's egress failed: {0}")]
    EgressFailed(String),
}

pub type Result<T> = std::result::Result<T, Error>;
