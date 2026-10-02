//! What the sandbox helper builds (kiln spec §9.2). The library writes a [`Plan`] and
//! runs `vmkit-sandbox run <plan.json>`; the helper does the namespace work.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One file or directory the VMM may see, attached by file descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bind {
    /// Host path; opened with `O_NOFOLLOW` semantics (a symlink is refused).
    pub source: PathBuf,
    /// Absolute path inside the sandbox root.
    pub target: PathBuf,
    pub writable: bool,
}

/// Resource limits applied to the VMM process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub open_files: u64,
    pub processes: u64,
}

/// The VM's network (kiln spec §9.3): set up in its namespace before the VMM starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPlan {
    /// `ip` and `nft`, run inside the namespace before the root is replaced.
    pub ip: PathBuf,
    pub nft: PathBuf,
    /// The nftables ruleset, loaded with `nft -f -`.
    pub ruleset: String,
    /// `pasta` and its options; the helper adds the namespace to attach to.
    pub pasta: PathBuf,
    pub pasta_args: Vec<String>,
}

/// Everything the helper needs to start one VMM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// The VMM binary on the host; it appears at `/vmm` inside.
    pub vmm: PathBuf,
    /// Arguments, already in terms of in-sandbox paths.
    pub args: Vec<String>,
    /// Files and directories under `/vm` (and the device nodes under `/dev`).
    pub binds: Vec<Bind>,
    pub limits: Limits,
    /// Host directory the tmpfs root is mounted on while it is built.
    pub root: PathBuf,
    /// The helper writes the VMM's host PID here.
    pub pid_file: PathBuf,
    pub net: Option<NetPlan>,
}
