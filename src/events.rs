//! Cloud Hypervisor's `--event-monitor` stream: a sequence of JSON objects.

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;

use crate::process::Proc;

/// Reads a file the VMM is still writing, like `tail -f`, until the VMM exits.
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
                self.file = File::open(&self.path).ok();
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

/// Reads events until the stream ends, calling `on_reset` on the first reset.
pub(crate) fn watch(stream: impl Read, mut on_reset: impl FnMut()) {
    for event in serde_json::Deserializer::from_reader(stream).into_iter::<Value>() {
        match event {
            Ok(e) if is_reset(&e) => return on_reset(),
            Ok(_) => {}
            Err(_) => return,
        }
    }
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
        let mut resets = 0;
        watch(STREAM.as_bytes(), || resets += 1);
        assert_eq!(resets, 1);
        let mut resets = 0;
        watch(
            &STREAM.as_bytes()[..STREAM
                .find("\n\n{\n  \"timestamp\": {\"secs\": 2, \"nanos\": 682")
                .unwrap()],
            || resets += 1,
        );
        assert_eq!(resets, 0, "a virtio device reset alone is not a VM reset");
    }
}
