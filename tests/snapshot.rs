//! Snapshot and restore on both backends (lazy-restore design §4.7), run on an otherwise
//! idle host like `tests/pause.rs`: Cloud Hypervisor 53 on aarch64 can leave a guest stuck
//! after a resume when other VMs load the host. Run with `--test-threads=1`; same environment
//! variables as `tests/contract.rs`.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use common::{Case, END};
use vmkit::lazy::{ChunkSource, LAZY_FILE, LazyIndex, split};
use vmkit::{Backend, Disk, Error, RestoreDisk, RestoreSpec, SnapshotBundle, Vm, VmSpec, VsockSpec};

const VSOCK_PORT: u32 = 1234;

/// The `VMKIT-COUNT` values in `console`, in order.
fn counts(console: &str) -> Vec<u64> {
    console
        .lines()
        .filter_map(|l| l.split("VMKIT-COUNT ").nth(1))
        .filter_map(|r| r.split_whitespace().next()?.parse().ok())
        .collect()
}

/// A counting guest with a writable disk and vsock.
fn counting_spec(c: &Case, mark: &str) -> VmSpec {
    let mut spec = c.spec("count");
    spec.cmdline.push(format!("vmkit.mark={mark}"));
    spec.cmdline.push(format!("vmkit.vsock={VSOCK_PORT}"));
    let disk = c.dir.path().join("disk.img");
    std::fs::File::create(&disk).unwrap().set_len(16 << 20).unwrap();
    spec.disks = vec![Disk {
        path: disk,
        read_only: false,
    }];
    spec.vsock = Some(VsockSpec { guest_cid: 3 });
    spec
}

/// A restore into a run directory of its own.
struct Restored {
    dir: tempfile::TempDir,
    vm: Box<dyn Vm>,
}

impl Restored {
    fn console(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("console.log")).unwrap_or_default()
    }

    /// Waits until the restored guest has printed `n` counts.
    fn await_counts(&self, n: usize) -> Vec<u64> {
        let deadline = Instant::now() + END;
        loop {
            let seen = counts(&self.console());
            if seen.len() >= n {
                return seen;
            }
            assert!(
                Instant::now() < deadline,
                "the restored guest printed {} counts; console:\n{}",
                seen.len(),
                self.console()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn restore(c: &Case, bundle: &SnapshotBundle) -> Restored {
    restore_from(c, bundle, None)
}

fn restore_from(c: &Case, bundle: &SnapshotBundle, chunks: Option<Arc<dyn ChunkSource>>) -> Restored {
    let dir = tempfile::tempdir().unwrap();
    let rs = RestoreSpec {
        disks: vec![RestoreDisk::Captured],
        console_log: dir.path().join("console.log"),
        run_dir: dir.path().to_path_buf(),
        net: None,
        chunks,
        scratch_dir: None,
    };
    let mut vm = c.vmm.restore(bundle, &rs).expect("restore");
    vm.resume().expect("resume");
    Restored { dir, vm }
}

/// Boots a counting guest, snapshots it once it has counted a few times, and kills it.
/// Returns the bundle and the last count before the snapshot.
fn snapshot_a_counting_guest(c: &Case, mark: &str) -> (SnapshotBundle, u64) {
    let mut vm = c.vmm.create(&counting_spec(c, mark)).expect("create");
    vm.start().unwrap();
    c.await_console("VMKIT-COUNT", 5);
    let bundle = vm.snapshot(&c.dir.path().join("bundle")).expect("snapshot");
    let at = *counts(&c.console()).last().unwrap();
    vm.kill().unwrap();
    (bundle, at)
}

/// A fingerprint of every file in the bundle.
fn fingerprint(dir: &Path) -> Vec<(PathBuf, u64, u64)> {
    use std::hash::{DefaultHasher, Hasher};
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let bytes = std::fs::read(&p).unwrap();
            let mut h = DefaultHasher::new();
            h.write(&bytes);
            (p, bytes.len() as u64, h.finish())
        })
        .collect();
    out.sort();
    out
}

fn snapshot_and_restore_continue_the_guest(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let (bundle, at) = snapshot_a_counting_guest(&c, "first");
    let disk = std::fs::read(bundle.dir.join("disk-0")).unwrap();
    assert!(
        disk.starts_with(b"VMKIT-MARK-first\n"),
        "the captured disk holds the mark"
    );

    let r = restore(&c, &bundle);
    // The host listens on the new run directory's vsock socket only now, and answers the
    // guest's next connection (which blocks its loop until it does).
    let listener = UnixListener::bind(format!(
        "{}_{VSOCK_PORT}",
        r.vm.vsock_socket().expect("vsock").display()
    ))
    .unwrap();
    let answered = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut line = String::new();
        BufReader::new(&conn).read_line(&mut line).unwrap();
        conn.write_all(b"after-restore\n").unwrap();
        line
    });
    let seen = r.await_counts(5);
    assert!(
        seen[0] == at || seen[0] == at + 1,
        "the guest went on from {at}, not from {}: {seen:?}",
        seen[0]
    );
    assert!(seen.windows(2).all(|w| w[1] == w[0] + 1), "{seen:?}");
    let console = r.console();
    assert!(
        !console.contains("VMKIT-GUEST-UP"),
        "the guest booted again:\n{console}"
    );
    assert!(console.contains("VMKIT-MARK-first"), "the disk reads back:\n{console}");

    // Connections the guest makes after the restore reach the host.
    assert_eq!(answered.join().unwrap(), "VMKIT-VSOCK-HELLO\n");
    let deadline = Instant::now() + END;
    while !r.console().contains("VMKIT-VSOCK-REPLY after-restore") {
        assert!(Instant::now() < deadline, "no vsock reply; console:\n{}", r.console());
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn a_bundle_restores_twice_and_is_never_written(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let (bundle, at) = snapshot_a_counting_guest(&c, "twice");
    let before = fingerprint(&bundle.dir);
    for _ in 0..2 {
        let mut r = restore(&c, &bundle);
        let seen = r.await_counts(3);
        assert!(seen[0] == at || seen[0] == at + 1, "{at}: {seen:?}");
        r.vm.kill().unwrap();
    }
    assert_eq!(fingerprint(&bundle.dir), before);
}

/// A bundle with the right shape for `c`'s backend but no real content, then `edit`ed.
fn fake_bundle(c: &Case, edit: impl FnOnce(&Path, &mut serde_json::Value)) -> Result<(), Error> {
    let dir = tempfile::tempdir().unwrap();
    let probe = tempfile::tempdir().unwrap();
    // The backend's own file names, and its version as `--version` prints it.
    let (state, memory): (&[&str], &str) = match c.vmm.name() {
        "firecracker" => (&["vmstate"], "memory"),
        _ => (&["config.json", "state.json"], "memory-ranges"),
    };
    let version = String::from_utf8(
        std::process::Command::new(match c.vmm.name() {
            "firecracker" => std::env::var("VMKIT_FIRECRACKER").unwrap_or("firecracker".into()),
            _ => std::env::var("VMKIT_CLOUD_HYPERVISOR").unwrap_or("cloud-hypervisor".into()),
        })
        .arg("--version")
        .output()
        .unwrap()
        .stdout,
    )
    .unwrap();
    let version = version
        .split_whitespace()
        .find_map(|t| t.strip_prefix('v'))
        .map(|v| {
            let mut parts: Vec<&str> = v.split('.').collect();
            parts.resize(3, "0");
            parts.join(".")
        })
        .unwrap();
    let mut files: Vec<serde_json::Value> = state
        .iter()
        .map(|n| serde_json::json!({"name": n, "role": "state"}))
        .collect();
    files.push(serde_json::json!({"name": memory, "role": "memory"}));
    files.push(serde_json::json!({"name": "disk-0", "role": "disk"}));
    for n in state {
        std::fs::write(dir.path().join(n), b"{}").unwrap();
    }
    std::fs::File::create(dir.path().join(memory))
        .unwrap()
        .set_len(64 << 20)
        .unwrap();
    std::fs::File::create(dir.path().join("disk-0"))
        .unwrap()
        .set_len(1 << 20)
        .unwrap();
    let mut info = serde_json::json!({
        "arch": std::env::consts::ARCH,
        "disks": [{"captured": true, "read_only": false, "size": 1 << 20}],
        "files": files,
        "memory_mib": 64,
        "net": false,
        "vcpus": 1,
        "version": 1,
        "vmm": {"name": c.vmm.name(), "version": version},
        "vsock": null,
    });
    edit(dir.path(), &mut info);
    std::fs::write(dir.path().join("bundle.json"), info.to_string()).unwrap();
    let rs = RestoreSpec {
        disks: vec![RestoreDisk::Captured],
        console_log: probe.path().join("console.log"),
        run_dir: probe.path().to_path_buf(),
        net: None,
        chunks: None,
        scratch_dir: None,
    };
    c.vmm
        .restore(
            &SnapshotBundle {
                dir: dir.path().to_path_buf(),
            },
            &rs,
        )
        .map(|_| ())
}

fn restore_refuses_a_foreign_or_tampered_bundle(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let refused = |what: &str, r: Result<(), Error>| match r {
        Err(Error::Snapshot(m)) => m,
        other => panic!("{what}: expected a snapshot error, got {other:?}"),
    };
    let other = if c.vmm.name() == "firecracker" {
        "cloud-hypervisor"
    } else {
        "firecracker"
    };
    refused("vmm", fake_bundle(&c, |_, i| i["vmm"]["name"] = other.into()));
    refused("version", fake_bundle(&c, |_, i| i["vmm"]["version"] = "0.0.1".into()));
    refused("arch", fake_bundle(&c, |_, i| i["arch"] = "riscv64".into()));
    refused("key", fake_bundle(&c, |_, i| i["kernel"] = "/etc/shadow".into()));
    refused(
        "short memory",
        fake_bundle(&c, |d, i| {
            let memory = i["files"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["role"] == "memory")
                .unwrap()["name"]
                .as_str()
                .unwrap()
                .to_string();
            std::fs::File::options()
                .write(true)
                .open(d.join(memory))
                .unwrap()
                .set_len((64 << 20) - 4096)
                .unwrap();
        }),
    );
    refused(
        "symlink",
        fake_bundle(&c, |d, _| {
            std::fs::remove_file(d.join("disk-0")).unwrap();
            std::os::unix::fs::symlink("/etc/passwd", d.join("disk-0")).unwrap();
        }),
    );
}

/// Chunks in memory, counting what is fetched, optionally lying about one chunk.
#[derive(Default)]
struct Chunks {
    chunks: Mutex<HashMap<String, Vec<u8>>>,
    fetched: AtomicU64,
    corrupt: Mutex<Option<String>>,
}

impl ChunkSource for Chunks {
    fn fetch(&self, digest: &str, _size: u64) -> std::io::Result<Vec<u8>> {
        let mut bytes = self
            .chunks
            .lock()
            .unwrap()
            .get(digest)
            .cloned()
            .ok_or(std::io::ErrorKind::NotFound)?;
        self.fetched.fetch_add(bytes.len() as u64, Ordering::SeqCst);
        if self.corrupt.lock().unwrap().as_deref() == Some(digest) {
            bytes[0] ^= 1;
        }
        Ok(bytes)
    }
}

/// `bundle` as a registry would hand it out lazily: only `bundle.json` and `lazy.json` in a
/// directory, every other file's chunks in the returned source.
fn lazy_bundle(bundle: &SnapshotBundle, dir: &Path) -> (SnapshotBundle, Arc<Chunks>, LazyIndex) {
    let chunks = Arc::new(Chunks::default());
    let mut files = std::collections::BTreeMap::new();
    for f in bundle.info().unwrap().files {
        let mut file = std::fs::File::open(bundle.dir.join(&f.name)).unwrap();
        let entry = split(&mut file, 1 << 20, &mut |d, bytes| {
            chunks.chunks.lock().unwrap().insert(d.to_string(), bytes.to_vec());
        })
        .unwrap();
        files.insert(f.name, entry);
    }
    let index = LazyIndex {
        version: 1,
        chunk_size: 1 << 20,
        files,
    };
    std::fs::copy(bundle.dir.join("bundle.json"), dir.join("bundle.json")).unwrap();
    std::fs::write(dir.join(LAZY_FILE), serde_json::to_vec(&index).unwrap()).unwrap();
    (SnapshotBundle { dir: dir.to_path_buf() }, chunks, index)
}

fn lazy_restore_continues_the_guest_and_fetches_only_what_it_touches(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let (bundle, at) = snapshot_a_counting_guest(&c, "lazy");
    let lazy_dir = tempfile::tempdir().unwrap();
    let (lazy, chunks, index) = lazy_bundle(&bundle, lazy_dir.path());
    let info = bundle.info().unwrap();
    let memory = info.memory_file().unwrap();
    let data_bytes = |name: &str| -> u64 {
        let f = &index.files[name];
        (0..f.chunks.len())
            .filter(|&i| f.chunks[i].is_some())
            .map(|i| f.chunk_len(index.chunk_size, i))
            .sum()
    };
    let memory_data = data_bytes(memory);
    let state: u64 = info
        .files
        .iter()
        .filter(|f| f.role == vmkit::Role::State)
        .map(|f| data_bytes(&f.name))
        .sum();

    let dir = tempfile::tempdir().unwrap();
    let rs = RestoreSpec {
        disks: vec![RestoreDisk::Captured],
        console_log: dir.path().join("console.log"),
        run_dir: dir.path().to_path_buf(),
        net: None,
        chunks: Some(chunks.clone()),
        scratch_dir: None,
    };
    let mut vm = c.vmm.restore(&lazy, &rs).expect("lazy restore");
    // What the restore itself needed, before the guest ran.
    let at_restore = chunks.fetched.load(Ordering::SeqCst);
    vm.resume().unwrap();
    let r = Restored { dir, vm };
    let seen = r.await_counts(5);
    assert!(seen[0] == at || seen[0] == at + 1, "{at}: {seen:?}");
    assert!(
        r.console().contains("VMKIT-MARK-lazy"),
        "the disk reads back:\n{}",
        r.console()
    );
    let fetched = chunks.fetched.load(Ordering::SeqCst);
    let disk = data_bytes("disk-0");
    eprintln!(
        "{}: fetched {at_restore} bytes to restore, {fetched} after 5 ticks; memory has {memory_data} data bytes of {} MiB, state {state}, disk {disk}",
        c.vmm.name(),
        info.memory_mib
    );
    if c.vmm.capabilities().lazy_memory {
        // The VMM resumed with only its state: memory comes in as the guest touches it.
        assert!(
            at_restore < state + memory_data / 4,
            "{at_restore} fetched before the guest ran"
        );
    } else {
        // Copy mode reads every memory data chunk before the restore returns.
        assert!(
            at_restore >= state + memory_data,
            "{at_restore} < {state} + {memory_data}"
        );
    }
    // Zero chunks are never fetched, and nothing is fetched twice.
    assert!(fetched <= state + memory_data + disk, "{fetched} fetched");
    assert!(
        lazy_dir.path().read_dir().unwrap().count() == 2,
        "the lazy bundle is never written"
    );
}

fn a_tampered_state_chunk_fails_the_restore(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let (bundle, _) = snapshot_a_counting_guest(&c, "tampered");
    let lazy_dir = tempfile::tempdir().unwrap();
    let (lazy, chunks, index) = lazy_bundle(&bundle, lazy_dir.path());
    let state = bundle
        .info()
        .unwrap()
        .files
        .into_iter()
        .find(|f| f.role == vmkit::Role::State)
        .unwrap();
    *chunks.corrupt.lock().unwrap() = index.files[&state.name].chunks.iter().flatten().next().cloned();
    let dir = tempfile::tempdir().unwrap();
    let rs = RestoreSpec {
        disks: vec![RestoreDisk::Captured],
        console_log: dir.path().join("console.log"),
        run_dir: dir.path().to_path_buf(),
        net: None,
        chunks: Some(chunks),
        scratch_dir: None,
    };
    match c.vmm.restore(&lazy, &rs) {
        Err(Error::Snapshot(m)) => assert!(m.contains(&state.name), "{m}"),
        Err(e) => panic!("expected a snapshot error, got {e}"),
        Ok(_) => panic!("a tampered chunk restored"),
    }
    let log = std::fs::read_to_string(dir.path().join("lazy.log")).unwrap();
    assert!(log.contains("not the chunk"), "{log}");
}

#[test]
fn firecracker_lazy_restore_continues_the_guest_and_fetches_only_what_it_touches() {
    lazy_restore_continues_the_guest_and_fetches_only_what_it_touches(Backend::Firecracker)
}

#[test]
fn cloud_hypervisor_lazy_restore_continues_the_guest_and_fetches_only_what_it_touches() {
    lazy_restore_continues_the_guest_and_fetches_only_what_it_touches(Backend::CloudHypervisor)
}

#[test]
fn firecracker_a_tampered_state_chunk_fails_the_restore() {
    a_tampered_state_chunk_fails_the_restore(Backend::Firecracker)
}

#[test]
fn cloud_hypervisor_a_tampered_state_chunk_fails_the_restore() {
    a_tampered_state_chunk_fails_the_restore(Backend::CloudHypervisor)
}

#[test]
fn firecracker_snapshot_and_restore_continue_the_guest() {
    snapshot_and_restore_continue_the_guest(Backend::Firecracker)
}

#[test]
fn cloud_hypervisor_snapshot_and_restore_continue_the_guest() {
    snapshot_and_restore_continue_the_guest(Backend::CloudHypervisor)
}

#[test]
fn firecracker_a_bundle_restores_twice_and_is_never_written() {
    a_bundle_restores_twice_and_is_never_written(Backend::Firecracker)
}

#[test]
fn cloud_hypervisor_a_bundle_restores_twice_and_is_never_written() {
    a_bundle_restores_twice_and_is_never_written(Backend::CloudHypervisor)
}

#[test]
fn firecracker_restore_refuses_a_foreign_or_tampered_bundle() {
    restore_refuses_a_foreign_or_tampered_bundle(Backend::Firecracker)
}

#[test]
fn cloud_hypervisor_restore_refuses_a_foreign_or_tampered_bundle() {
    restore_refuses_a_foreign_or_tampered_bundle(Backend::CloudHypervisor)
}
