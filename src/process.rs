//! The VMM child process: spawning, readiness, kill and wait.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::http;
use crate::spec::{EndReason, VmEnd};

/// How long a VMM may take to open its API socket.
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(10);
/// How long after a failed API call to look for the VMM's exit before blaming the socket.
const DEATH_GRACE: Duration = Duration::from_millis(500);

/// Opens `path`, a file the VMM may have written or replaced, for reading. A symlink as the
/// final component is refused (`O_NOFOLLOW`), a FIFO cannot block the open (`O_NONBLOCK`),
/// and anything but a regular file is refused.
pub(crate) fn open_vmm_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(file)
}

/// Creates `path` afresh in a directory the VMM can write: whatever is there (a symlink, say)
/// is removed, not followed or truncated.
pub(crate) fn create_vmm_file(path: &Path) -> io::Result<File> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// The text of a VMM log, or nothing if it is missing or not a regular file.
fn read_vmm_log(path: &Path) -> String {
    let mut text = String::new();
    if let Ok(mut f) = open_vmm_file(path) {
        let _ = io::Read::read_to_string(&mut f, &mut text);
    }
    text
}

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

/// Kills the sandboxed VMM whose PID is in `file`, if it is still the child of the helper
/// `helper` (a stale file or a reused PID is ignored). True if the signal was sent.
#[cfg(target_os = "linux")]
fn kill_vmm(file: &Path, helper: u32) -> bool {
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
    let Some(pid) = std::fs::read_to_string(file)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
    else {
        return false;
    };
    let Some(fd) = Pid::from_raw(pid).and_then(|p| pidfd_open(p, PidfdFlags::empty()).ok()) else {
        return false;
    };
    // Checked after opening the pidfd, so the signal goes to the process that was checked.
    let parent = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("PPid:"))
                .and_then(|v| v.trim().parse::<u32>().ok())
        });
    parent == Some(helper) && pidfd_send_signal(&fd, Signal::KILL).is_ok()
}

#[cfg(not(target_os = "linux"))]
fn kill_vmm(_file: &Path, _helper: u32) -> bool {
    false
}

/// A running VMM. Shared with the Cloud Hypervisor reset backstop, which may kill it.
#[derive(Clone)]
pub(crate) struct Proc {
    child: Arc<Mutex<Child>>,
    killed: Arc<AtomicBool>,
    reset_stopped: Arc<AtomicBool>,
    backstop_failed: Arc<AtomicBool>,
    end: Arc<Mutex<Option<VmEnd>>>,
    /// Files with the VMM's own messages, quoted when it exits before its API is up.
    logs: Vec<PathBuf>,
    /// For a sandboxed VMM: the file with its host PID (see [`Proc::with_vmm_pid_file`]).
    vmm_pid_file: Option<PathBuf>,
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
        backstop_failed: Arc::new(AtomicBool::new(false)),
        end: Arc::new(Mutex::new(None)),
        logs: vec![log.to_path_buf()],
        vmm_pid_file: None,
    })
}

impl Proc {
    /// Also quotes `path`, a log the VMM writes itself, when the VMM exits early.
    pub(crate) fn with_log(mut self, path: &Path) -> Self {
        self.logs.push(path.to_path_buf());
        self
    }

    /// The child is the sandbox helper, and the VMM it runs has its host PID in `path`.
    /// Killing then kills the VMM itself: the helper reaps it and ends the same way, so
    /// when the child has ended, so has the VMM.
    pub(crate) fn with_vmm_pid_file(mut self, path: &Path) -> Self {
        self.vmm_pid_file = Some(path.to_path_buf());
        self
    }

    /// The last lines of the VMM's logs, for error messages (empty when there are none).
    pub(crate) fn log_tail(&self) -> String {
        let mut tail = Vec::new();
        for log in &self.logs {
            let text = read_vmm_log(log);
            let lines: Vec<&str> = text.lines().collect();
            tail.extend(lines[lines.len().saturating_sub(5)..].iter().map(|l| l.to_string()));
        }
        tail.join(" | ")
    }

    fn early_exit(&self, end: VmEnd) -> Error {
        Error::EarlyExit(format!("{end:?}: {}", self.log_tail()))
    }

    /// Waits until `socket` accepts connections, failing early if the VMM exits.
    pub(crate) fn wait_for_socket(&self, socket: &Path) -> Result<()> {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if let Some(end) = self.try_end()? {
                return Err(self.early_exit(end));
            }
            if UnixStream::connect(socket).is_ok() {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(Error::Timeout(format!(
                    "the VMM API socket (VMM log: {})",
                    self.log_tail()
                )));
            }
            std::thread::sleep(POLL);
        }
    }

    /// One API request. If the socket fails because the VMM died, the error says so (with the
    /// end of its logs) rather than reporting a bare I/O error.
    pub(crate) fn request(
        &self,
        socket: &Path,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<http::Response> {
        match http::request(socket, method, path, body) {
            Err(Error::Io(io)) => {
                // The exit may be a moment behind the closed connection.
                match self.wait(Some(DEATH_GRACE))? {
                    Some(end) => Err(self.early_exit(end)),
                    None => Err(Error::Io(io)),
                }
            }
            other => other,
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
        let result = self.signal_kill();
        if result.is_err() {
            // Not stopped after all: the backstop reports its failure instead.
            self.reset_stopped.store(false, Ordering::SeqCst);
        }
        result
    }

    /// Kills the VMM because the reset backstop can no longer watch it (idempotent).
    pub(crate) fn fail_backstop(&self) -> Result<()> {
        if self.try_end()?.is_some() {
            return Ok(());
        }
        self.backstop_failed.store(true, Ordering::SeqCst);
        self.signal_kill()
    }

    fn signal_kill(&self) -> Result<()> {
        let mut child = self.child.lock().expect("not poisoned");
        if let Some(file) = &self.vmm_pid_file {
            if kill_vmm(file, child.id()) {
                return Ok(());
            }
        }
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
        } else if self.backstop_failed.load(Ordering::SeqCst) {
            EndReason::BackstopFailed
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
        if end.is_none() {
            if let Some(status) = self.child.lock().expect("not poisoned").try_wait()? {
                *end = Some(self.end_from(status));
            }
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

        let p = sh("sleep 30", dir.path());
        p.fail_backstop().unwrap();
        let end = p.wait(None).unwrap().unwrap();
        assert_eq!((end.reason, end.signal), (EndReason::BackstopFailed, Some(9)));
        p.fail_backstop().unwrap();
    }

    #[test]
    fn failing_the_backstop_of_a_finished_process_keeps_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let p = sh("exit 0", dir.path());
        assert_eq!(
            p.wait(Some(Duration::from_secs(5))).unwrap().unwrap().reason,
            EndReason::Exited
        );
        p.fail_backstop().unwrap();
        assert_eq!(p.wait(None).unwrap().unwrap().reason, EndReason::Exited);
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
    fn log_tail_quotes_the_stderr_and_the_own_logs() {
        let dir = tempfile::tempdir().unwrap();
        let own_log = dir.path().join("own.log");
        std::fs::write(&own_log, "a\nb\nc\nd\ne\nf\ng\n").unwrap();
        let p = sh("echo 'it broke' >&2", dir.path()).with_log(&own_log);
        p.wait(None).unwrap();
        let tail = p.log_tail();
        assert!(tail.contains("it broke"), "{tail}");
        assert!(tail.ends_with("c | d | e | f | g"), "five lines of each log: {tail}");
    }

    #[test]
    fn vmm_files_are_never_reached_through_a_symlink_or_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "do not read or truncate\n").unwrap();
        let log = dir.path().join("vmm.log");
        std::os::unix::fs::symlink(&secret, &log).unwrap();
        let p = sh("exit 0", dir.path()).with_log(&log);
        p.wait(None).unwrap();
        assert!(!p.log_tail().contains("do not read"), "{}", p.log_tail());
        assert_eq!(open_vmm_file(&log).unwrap_err().raw_os_error(), Some(libc::ELOOP));
        // Creating replaces the symlink and leaves its target alone.
        create_vmm_file(&log).unwrap();
        assert_eq!(std::fs::read_to_string(&secret).unwrap(), "do not read or truncate\n");
        assert!(std::fs::symlink_metadata(&log).unwrap().is_file());
        // A FIFO neither blocks the open nor is read.
        let fifo = dir.path().join("fifo");
        assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let err = open_vmm_file(&fifo).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
    }

    #[test]
    fn a_failed_request_after_the_vmm_died_is_an_early_exit() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        // The "VMM" dies shortly after the connection drops.
        let p = sh("echo 'vmm exploded' >&2; sleep 0.2", dir.path());
        let server = std::thread::spawn(move || drop(listener.accept().unwrap()));
        let err = p.request(&sock, "PUT", "/x", None).unwrap_err();
        server.join().unwrap();
        assert!(
            matches!(&err, Error::EarlyExit(m) if m.contains("vmm exploded")),
            "{err}"
        );

        // A VMM that is still alive leaves the I/O error alone.
        let live = sh("sleep 30", dir.path());
        let err = live
            .request(&dir.path().join("missing.sock"), "PUT", "/x", None)
            .unwrap_err();
        live.kill().unwrap();
        assert!(matches!(err, Error::Io(_)), "{err}");
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
