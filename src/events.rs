//! Cloud Hypervisor's `--event-monitor` stream: a sequence of JSON objects.

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;

use crate::process::Proc;

/// Reads a file the VMM is still writing, like `tail -f`, until the VMM exits. The VMM can
/// replace the file: a symlink or anything but a regular file is a read error (failing closed),
/// never followed and never blocking.
pub(crate) struct Tail {
    path: PathBuf,
    file: Option<File>,
    proc: Proc,
}

impl Tail {
    pub(crate) fn new(path: PathBuf, proc: Proc) -> Self {
        Self { path, file: None, proc }
    }
}

impl Read for Tail {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.file.is_none() {
                match crate::process::open_vmm_file(&self.path) {
                    Ok(f) => self.file = Some(f),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            if let Some(f) = &mut self.file {
                let n = f.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
            }
            // Nothing new: stop once the VMM has exited and everything was read.
            if self.proc.try_end().map_err(io::Error::other)?.is_some() {
                return match &mut self.file {
                    Some(f) => f.read(buf),
                    None => Ok(0),
                };
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The event a guest reset produces; the VMM would otherwise reboot the VM.
pub(crate) fn is_reset(event: &Value) -> bool {
    event["source"] == "vm" && event["event"] == "rebooting"
}

/// How watching the event stream ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Watch {
    /// The guest reset: the VMM must be stopped.
    Reset,
    /// The stream ended cleanly (the VMM exited).
    Ended,
    /// The stream could not be read, so resets can no longer be seen: fail closed.
    Failed(String),
}

/// Reads events until the first reset, the end of the stream, or an error.
pub(crate) fn watch(stream: impl Read) -> Watch {
    for event in serde_json::Deserializer::from_reader(stream).into_iter::<Value>() {
        match event {
            Ok(e) if is_reset(&e) => return Watch::Reset,
            Ok(_) => {}
            // `Tail` ends the stream only once the VMM exited, so a cut-off last event is harmless.
            Err(e) if e.is_eof() => return Watch::Ended,
            Err(e) => return Watch::Failed(e.to_string()),
        }
    }
    Watch::Ended
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from Cloud Hypervisor v53 for a guest `reboot -f`.
    const STREAM: &str = r#"{
  "timestamp": {"secs": 0, "nanos": 150720},
  "source": "vmm",
  "event": "starting",
  "properties": null
}

{
  "timestamp": {"secs": 2, "nanos": 676003268},
  "source": "virtio-device",
  "event": "reset",
  "properties": {"id": "__rng"}
}

{
  "timestamp": {"secs": 2, "nanos": 682140329},
  "source": "vm",
  "event": "rebooting",
  "properties": null
}
"#;

    #[test]
    fn stops_at_the_vm_reboot_event_not_a_device_reset() {
        assert_eq!(watch(STREAM.as_bytes()), Watch::Reset);
        let before_reboot = &STREAM.as_bytes()[..STREAM
            .find("\n\n{\n  \"timestamp\": {\"secs\": 2, \"nanos\": 682")
            .unwrap()];
        assert_eq!(
            watch(before_reboot),
            Watch::Ended,
            "a virtio device reset alone is not a VM reset"
        );
    }

    #[test]
    fn a_malformed_stream_fails_closed() {
        assert!(matches!(
            watch(&b"{\"source\": \"vmm\"}\n garbage"[..]),
            Watch::Failed(_)
        ));
        assert!(matches!(watch(&b"{\"source\": 1 2}"[..]), Watch::Failed(_)));
    }

    #[test]
    fn a_cut_off_last_event_is_just_the_end() {
        assert_eq!(watch(&b"{\"source\": \"vm\", \"ev"[..]), Watch::Ended);
    }

    #[test]
    fn tail_follows_a_file_the_vmm_is_still_writing() {
        let dir = tempfile::tempdir().unwrap();
        let events = dir.path().join("events.json");
        let script = format!(
            "sleep 0.3; printf '{{\"source\":\"vmm\",\"event\":\"starting\"}}' >> {0}; sleep 0.2; \
             printf '{{\"source\":\"vm\",\"event\":\"rebooting\"}}' >> {0}; sleep 0.2",
            events.display()
        );
        let proc = crate::process::spawn(
            std::path::Path::new("/bin/sh"),
            &["-c".into(), script],
            &dir.path().join("console"),
            &dir.path().join("log"),
        )
        .unwrap();
        assert_eq!(watch(Tail::new(events.clone(), proc.clone())), Watch::Reset);
        proc.kill().unwrap();
    }

    #[test]
    fn a_symlinked_or_fifo_event_stream_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        std::fs::write(&target, "{\"source\":\"vmm\"}").unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let fifo = dir.path().join("fifo.json");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let proc = crate::process::spawn(
            std::path::Path::new("/bin/sh"),
            &["-c".into(), "sleep 30".into()],
            &dir.path().join("console"),
            &dir.path().join("log"),
        )
        .unwrap();
        for path in [link, fifo] {
            assert!(
                matches!(watch(Tail::new(path.clone(), proc.clone())), Watch::Failed(_)),
                "{}",
                path.display()
            );
        }
        proc.kill().unwrap();
    }

    #[test]
    fn tail_ends_when_the_vmm_exits_without_events() {
        let dir = tempfile::tempdir().unwrap();
        let proc = crate::process::spawn(
            std::path::Path::new("/bin/sh"),
            &["-c".into(), "sleep 0.2".into()],
            &dir.path().join("console"),
            &dir.path().join("log"),
        )
        .unwrap();
        assert_eq!(watch(Tail::new(dir.path().join("never.json"), proc)), Watch::Ended);
    }
}
