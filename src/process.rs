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
    /// Files with the VMM's own messages, quoted when it exits before its API is up.
    logs: Vec<PathBuf>,
}

/// Starts `binary args...` with the guest serial (the VMM's stdout) appended to
/// `console_log` and the VMM's stderr in `log`.
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
        logs: vec![log.to_path_buf()],
    })
}

impl Proc {
    /// Also quotes `path`, a log the VMM writes itself, when the VMM exits early.
    pub(crate) fn with_log(mut self, path: &Path) -> Self {
        self.logs.push(path.to_path_buf());
        self
    }

    /// Waits until `socket` accepts connections, failing early if the VMM exits.
    pub(crate) fn wait_for_socket(&self, socket: &Path) -> Result<()> {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if let Some(end) = self.try_end()? {
                let mut tail = Vec::new();
                for log in &self.logs {
                    let text = std::fs::read_to_string(log).unwrap_or_default();
                    let lines: Vec<&str> = text.lines().collect();
                    tail.extend(lines[lines.len().saturating_sub(5)..].iter().map(|l| l.to_string()));
                }
                return Err(Error::EarlyExit(format!("{end:?}: {}", tail.join(" | "))));
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

    /// Kills the VMM (idempotent). A VMM that already ended keeps its own end reason.
    pub(crate) fn kill(&self) -> Result<()> {
        if self.try_end()?.is_some() {
            return Ok(());
        }
        self.killed.store(true, Ordering::SeqCst);
        self.signal_kill()
    }

    /// Kills the VMM because the guest reset (Cloud Hypervisor backstop).
    pub(crate) fn stop_on_reset(&self) -> Result<()> {
        if self.try_end()?.is_some() {
            return Ok(());
        }
        self.reset_stopped.store(true, Ordering::SeqCst);
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

        let p = sh("sleep 30", dir.path());
        p.stop_on_reset().unwrap();
        assert_eq!(p.wait(None).unwrap().unwrap().reason, EndReason::ResetStopped);
    }

    #[test]
    fn killing_a_finished_process_keeps_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let p = sh("exit 0", dir.path());
        let end = p.wait(Some(Duration::from_secs(5))).unwrap().unwrap();
        assert_eq!(end.reason, EndReason::Exited);
        p.kill().unwrap();
        assert_eq!(p.wait(None).unwrap().unwrap().reason, EndReason::Exited);
    }

    #[test]
    fn stopping_a_finished_process_on_reset_keeps_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let p = sh("exit 0", dir.path());
        assert_eq!(
            p.wait(Some(Duration::from_secs(5))).unwrap().unwrap().reason,
            EndReason::Exited
        );
        p.stop_on_reset().unwrap();
        assert_eq!(p.wait(None).unwrap().unwrap().reason, EndReason::Exited);
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
    fn early_exit_is_reported_with_the_vmm_logs() {
        let dir = tempfile::tempdir().unwrap();
        let own_log = dir.path().join("own.log");
        std::fs::write(&own_log, "first\nlogger says no\n").unwrap();
        let p = sh("echo 'bad flag' >&2; exit 1", dir.path()).with_log(&own_log);
        let err = p.wait_for_socket(&dir.path().join("never.sock")).unwrap_err();
        assert!(
            matches!(&err, Error::EarlyExit(msg) if msg.contains("bad flag") && msg.contains("logger says no")),
            "{err}"
        );
    }
}
