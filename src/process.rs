//! The VMM child process: spawning, readiness, kill and wait.

use std::fs::{File, OpenOptions};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::spec::{EndReason, VmEnd};

/// How long a VMM may take to open its API socket.
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(10);

/// Removes a socket a previous VMM left in the run directory; VMMs refuse to bind over it.
pub(crate) fn clear_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => Ok(std::fs::remove_file(path)?),
        Ok(_) => Err(Error::InvalidSpec(format!(
            "{} exists and is not a socket",
            path.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// A running VMM. Shared with the Cloud Hypervisor reset backstop, which may kill it.
#[derive(Clone)]
pub(crate) struct Proc {
    child: Arc<Mutex<Child>>,
    killed: Arc<AtomicBool>,
    reset_stopped: Arc<AtomicBool>,
    end: Arc<Mutex<Option<VmEnd>>>,
    log: PathBuf,
}

/// Starts `binary args...` with the guest serial (the VMM's stdout) appended to
/// `console_log` and the VMM's own messages in `log`.
pub(crate) fn spawn(binary: &Path, args: &[String], console_log: &Path, log: &Path) -> Result<Proc> {
    let console = OpenOptions::new().create(true).append(true).open(console_log)?;
    let log_file = File::create(log)?;
    let child = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(console)
        .stderr(log_file)
        .spawn()?;
    Ok(Proc {
        child: Arc::new(Mutex::new(child)),
        killed: Arc::new(AtomicBool::new(false)),
        reset_stopped: Arc::new(AtomicBool::new(false)),
        end: Arc::new(Mutex::new(None)),
        log: log.to_path_buf(),
    })
}

impl Proc {
    /// Waits until `socket` accepts connections, failing early if the VMM exits.
    pub(crate) fn wait_for_socket(&self, socket: &Path) -> Result<()> {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if let Some(end) = self.try_end()? {
                let tail = std::fs::read_to_string(&self.log).unwrap_or_default();
                let tail: String = tail
                    .lines()
                    .rev()
                    .take(5)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | ");
                return Err(Error::EarlyExit(format!("{end:?}: {tail}")));
            }
            if UnixStream::connect(socket).is_ok() {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(Error::Timeout("the VMM API socket"));
            }
            std::thread::sleep(POLL);
        }
    }

    /// Kills the VMM (idempotent).
    pub(crate) fn kill(&self) -> Result<()> {
        self.killed.store(true, Ordering::SeqCst);
        self.signal_kill()
    }

    fn signal_kill(&self) -> Result<()> {
        let mut child = self.child.lock().expect("not poisoned");
        match child.kill() {
            Ok(()) => Ok(()),
            // Already reaped: nothing to kill.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn end_from(&self, status: ExitStatus) -> VmEnd {
        let reason = if self.reset_stopped.load(Ordering::SeqCst) {
            EndReason::ResetStopped
        } else if self.killed.load(Ordering::SeqCst) {
            EndReason::Killed
        } else {
            EndReason::Exited
        };
        VmEnd {
            reason,
            code: status.code(),
            signal: status.signal(),
        }
    }

    /// The end, if the VMM has exited (non-blocking).
    pub(crate) fn try_end(&self) -> Result<Option<VmEnd>> {
        let mut end = self.end.lock().expect("not poisoned");
        if end.is_none()
            && let Some(status) = self.child.lock().expect("not poisoned").try_wait()?
        {
            *end = Some(self.end_from(status));
        }
        Ok(*end)
    }

    /// Waits up to `timeout` (forever when `None`) for the VMM to exit.
    pub(crate) fn wait(&self, timeout: Option<Duration>) -> Result<Option<VmEnd>> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            if let Some(end) = self.try_end()? {
                return Ok(Some(end));
            }
            if deadline.is_some_and(|d| Instant::now() > d) {
                return Ok(None);
            }
            std::thread::sleep(POLL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str, dir: &Path) -> Proc {
        spawn(
            Path::new("/bin/sh"),
            &["-c".into(), script.into()],
            &dir.join("console"),
            &dir.join("log"),
        )
        .unwrap()
    }

    #[test]
    fn reports_how_the_process_ended() {
        let dir = tempfile::tempdir().unwrap();
        let p = sh("echo serial; exit 3", dir.path());
        let end = p.wait(Some(Duration::from_secs(5))).unwrap().unwrap();
        assert_eq!((end.reason, end.code), (EndReason::Exited, Some(3)));
        assert_eq!(std::fs::read_to_string(dir.path().join("console")).unwrap(), "serial\n");

        let p = sh("sleep 30", dir.path());
        assert_eq!(p.wait(Some(Duration::from_millis(50))).unwrap(), None);
        p.kill().unwrap();
        let end = p.wait(None).unwrap().unwrap();
        assert_eq!((end.reason, end.signal), (EndReason::Killed, Some(9)));
        p.kill().unwrap();
    }

    #[test]
    fn console_is_appended_not_truncated() {
        let dir = tempfile::tempdir().unwrap();
        for word in ["one", "two"] {
            sh(&format!("echo {word}"), dir.path()).wait(None).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(dir.path().join("console")).unwrap(),
            "one\ntwo\n"
        );
    }

    #[test]
    fn early_exit_is_reported_with_the_vmm_log() {
        let dir = tempfile::tempdir().unwrap();
        let p = sh("echo 'bad flag' >&2; exit 1", dir.path());
        let err = p.wait_for_socket(&dir.path().join("never.sock")).unwrap_err();
        assert!(
            matches!(&err, Error::EarlyExit(msg) if msg.contains("bad flag")),
            "{err}"
        );
    }
}
