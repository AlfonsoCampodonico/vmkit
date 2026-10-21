//! What both drivers share for snapshot and restore (lazy-restore design §4): the shape a
//! bundle records, collecting what the VMM wrote, and the sandbox a restore runs in.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::bundle::{self, BundleInfo, BundleVsock, DiskInfo, Expect, FileInfo, Layout, Role, VmmId};
use crate::error::{Error, Result};
use crate::lazy::ChunkSource;
use crate::lazy::file::{LazyFile, Log};
use crate::lazy::{LAZY_FILE, LazyIndex};
use crate::sandbox::{self, Mount};
use crate::spec::{Disk, RestoreDisk, RestoreSpec, SnapshotBundle, VmSpec, VsockSpec};

/// The VMM's working directory for a snapshot, inside the sandbox (`<run_dir>/sock/snapshot`
/// on the host): `/vm/sock` is the only directory it may write.
pub(crate) const VMM_DIR: &str = "/vm/sock/snapshot";

/// A directory's identity, from `lstat` (so a symlink is never one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirId {
    dev: u64,
    ino: u64,
}

impl DirId {
    fn of(path: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_dir() {
            return Err(Error::Snapshot(format!("{} is not a directory", path.display())));
        }
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
        })
    }
}

/// What a running VM is, as a bundle records it.
#[derive(Clone)]
pub(crate) struct Shape {
    pub vmm: VmmId,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub vsock: Option<VsockSpec>,
    pub net: bool,
    /// The VM's NIC is on its caller's tap ([`crate::TapAttach`]), which a bundle cannot
    /// record: such a VM is never snapshotted.
    pub attached: bool,
    /// The host files behind the VM's disks, in order.
    pub disks: Vec<Disk>,
    pub run_dir: PathBuf,
    /// Lazily served disks: fetched in full before a snapshot copies them.
    pub lazy: Vec<Arc<LazyFile>>,
}

impl Shape {
    pub fn of(spec: &VmSpec, vmm: VmmId) -> Self {
        Self {
            lazy: Vec::new(),
            vmm,
            vcpus: spec.vcpus,
            memory_mib: spec.memory_mib,
            vsock: spec.vsock,
            net: spec.net.is_some(),
            attached: spec.tap.is_some(),
            disks: spec.disks.clone(),
            run_dir: spec.run_dir.clone(),
        }
    }

    fn info(&self, layout: Layout) -> Result<BundleInfo> {
        let mut files: Vec<FileInfo> = layout
            .state
            .iter()
            .map(|n| FileInfo {
                name: n.to_string(),
                role: Role::State,
            })
            .collect();
        files.push(FileInfo {
            name: layout.memory.into(),
            role: Role::Memory,
        });
        let mut disks = Vec::new();
        for (n, d) in self.disks.iter().enumerate() {
            disks.push(DiskInfo {
                read_only: d.read_only,
                size: std::fs::metadata(&d.path)?.len(),
                captured: !d.read_only,
            });
            if !d.read_only {
                files.push(FileInfo {
                    name: bundle::disk_file(n),
                    role: Role::Disk,
                });
            }
        }
        Ok(BundleInfo {
            version: bundle::BUNDLE_VERSION,
            vmm: self.vmm.clone(),
            arch: std::env::consts::ARCH.into(),
            vcpus: self.vcpus,
            memory_mib: self.memory_mib,
            net: self.net,
            vsock: self.vsock.map(|v| BundleVsock { guest_cid: v.guest_cid }),
            disks,
            files,
        })
    }

    /// Refuses a snapshot this shape cannot be restored from.
    pub fn check_snapshot(&self) -> Result<()> {
        if self.attached {
            return Err(Error::Unsupported("a snapshot of a VM on an attached tap"));
        }
        Ok(())
    }

    /// The host side of [`VMM_DIR`], emptied for a new snapshot; returns the directory's
    /// identity for [`Shape::finish`].
    pub fn vmm_dir(&self) -> Result<DirId> {
        let dir = self.run_dir.join("sock/snapshot");
        // The VMM may have left anything here; `remove_dir_all` never follows symlinks.
        match std::fs::remove_dir_all(&dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        std::fs::create_dir(&dir)?;
        DirId::of(&dir)
    }

    /// Collects the VMM's files from [`Shape::vmm_dir`] into `dest`, copies the writable
    /// disks, and writes `bundle.json` last, so a bundle with one is complete.
    ///
    /// The VMM can write `<run_dir>/sock`, so it could have swapped its snapshot directory for
    /// a symlink to a host directory. The directory is therefore first moved out of its reach
    /// (into `<run_dir>`, which the VMM never sees) and must still be the one `vmm_dir` made;
    /// from there only regular files are taken, never through a symlink.
    pub fn finish(&self, layout: Layout, dest: &Path, made: DirId) -> Result<SnapshotBundle> {
        let src = self.run_dir.join("snapshot-taken");
        match std::fs::remove_dir_all(&src) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        std::fs::rename(self.run_dir.join("sock/snapshot"), &src)?;
        if DirId::of(&src).ok() != Some(made) {
            // A symlink or another directory: never read through it, and leave its target be.
            let _ = std::fs::remove_file(&src);
            return Err(Error::Snapshot("the VMM replaced its snapshot directory".into()));
        }
        for f in &self.lazy {
            f.ensure_all()
                .map_err(|e| Error::Snapshot(format!("fetching {} before the snapshot: {e}", f.name())))?;
        }
        for name in layout.state.iter().chain([&layout.memory]) {
            bundle::take_file(&src.join(name), dest, name)?;
        }
        for (n, d) in self.disks.iter().enumerate().filter(|(_, d)| !d.read_only) {
            bundle::copy_sparse(&std::fs::File::open(&d.path)?, &dest.join(bundle::disk_file(n)))?;
        }
        bundle::write_info(dest, &self.info(layout)?)?;
        let _ = std::fs::remove_dir_all(&src);
        Ok(SnapshotBundle {
            dir: dest.to_path_buf(),
        })
    }
}

/// A checked bundle and the sandbox to restore it in.
pub(crate) struct Restore {
    pub info: BundleInfo,
    /// The VM as the sandbox sees it. Its kernel and initramfs are empty placeholders: the
    /// VMMs do not load them on restore, but Cloud Hypervisor's Landlock rules name them.
    pub spec: VmSpec,
    /// The snapshot files at `/vm/snapshot/<name>`, and for a lazy restore the FUSE mount at
    /// `/vm/lazy` with its files rebound over their usual places.
    pub mounts: Vec<Mount>,
    /// The lazily served disks, which a snapshot of the restored VM must fetch in full.
    pub lazy_disks: Vec<Arc<LazyFile>>,
}

/// The FUSE mount's place inside the sandbox.
const LAZY: &str = "/vm/lazy";

fn snapshot_target(name: &str) -> PathBuf {
    Path::new(sandbox::SNAPSHOT).join(name)
}

impl Restore {
    /// Checks `bundle` against the restoring backend and `rs`, and resolves its files and
    /// disks. The bundle is never written: captured disks are copied, or served lazily with a
    /// local copy-on-write backing, in the scratch directory.
    pub fn prepare(bundle: &SnapshotBundle, rs: &RestoreSpec, expect: &Expect) -> Result<Self> {
        if !rs.run_dir.is_dir() {
            return Err(Error::InvalidSpec(format!(
                "run_dir {} is not an existing directory",
                rs.run_dir.display()
            )));
        }
        let scratch = rs.scratch_dir.clone().unwrap_or_else(|| rs.run_dir.clone());
        let info = bundle.info()?;
        let index = match &rs.chunks {
            Some(_) => LazyIndex::read(&bundle.dir)?,
            None => None,
        };
        let local = |name: &str| std::fs::symlink_metadata(bundle.file(name)).is_ok();
        info.check(expect, &mut |name| {
            if local(name) {
                return bundle.local_size(name);
            }
            match index.as_ref().and_then(|i| i.files.get(name)) {
                Some(f) => Ok(f.size),
                None => Err(Error::Snapshot(format!(
                    "{name} is neither in the bundle nor in its lazy index"
                ))),
            }
        })?;
        if let Some(index) = &index
            && let Some(extra) = index.files.keys().find(|n| !info.files.iter().any(|f| &f.name == *n))
        {
            return Err(Error::Snapshot(format!(
                "{LAZY_FILE} names {extra}, which is not a file of the bundle"
            )));
        }
        if rs.net.is_some() != info.net {
            return Err(Error::Snapshot(if info.net {
                "the snapshot's VM had a NIC, so the restore needs a network".into()
            } else {
                "the snapshot's VM had no NIC, so the restore cannot add a network".into()
            }));
        }
        let placeholder = rs.run_dir.join("restore-placeholder");
        std::fs::File::create(&placeholder)?;

        // Files served lazily: everything the bundle directory lacks.
        let lazy_names: Vec<&FileInfo> = info.files.iter().filter(|f| !local(&f.name)).collect();
        let mut lazy = Lazy::default();
        if !lazy_names.is_empty() {
            let (Some(index), Some(source)) = (&index, &rs.chunks) else {
                return Err(Error::Snapshot(
                    "the bundle is incomplete and the restore has no chunk source".into(),
                ));
            };
            lazy = Lazy::open(index, source.clone(), &lazy_names, &scratch, &rs.run_dir)?;
        }

        // Disks: host files, local captured copies, or lazy files rebound over a placeholder.
        if rs.disks.len() != info.disks.len() {
            return Err(Error::Snapshot(format!(
                "the snapshot has {} disks, and the restore names {}",
                info.disks.len(),
                rs.disks.len()
            )));
        }
        let mut disks = Vec::new();
        let mut rebinds = Vec::new();
        for (n, (d, source)) in info.disks.iter().zip(&rs.disks).enumerate() {
            let name = bundle::disk_file(n);
            let path = match source {
                RestoreDisk::Captured if !d.captured => {
                    return Err(Error::Snapshot(format!(
                        "disk {n} was not captured: restore it from a host file"
                    )));
                }
                RestoreDisk::Captured if lazy.files.contains_key(&name) => {
                    rebinds.push((name.clone(), PathBuf::from(sandbox::disk(n)), true));
                    placeholder.clone()
                }
                RestoreDisk::Captured => {
                    let copy = scratch.join(&name);
                    bundle::copy_sparse(&crate::process::open_vmm_file(&bundle.file(&name))?, &copy)?;
                    copy
                }
                // A host file serves only a read-only disk, which bundles never capture. For a
                // writable disk it would be bound writable, letting the guest write a file the
                // caller shares (a base image, say), and a later snapshot would capture the
                // bundle's copy instead of what the guest wrote.
                RestoreDisk::Host(_) if !d.read_only => {
                    return Err(Error::Snapshot(format!(
                        "disk {n} is writable: restore it as RestoreDisk::Captured, not from a host file"
                    )));
                }
                RestoreDisk::Host(path) => {
                    let size = std::fs::File::open(path)?.metadata()?.len();
                    if size != d.size {
                        return Err(Error::Snapshot(format!(
                            "disk {n} was {} bytes, and {} is {size}",
                            d.size,
                            path.display()
                        )));
                    }
                    path.clone()
                }
            };
            disks.push(Disk {
                path,
                read_only: d.read_only,
            });
        }

        let mut mounts = Vec::new();
        for f in info.files.iter().filter(|f| f.role != Role::Disk) {
            let source = match (lazy.files.get(&f.name), lazy.state.get(&f.name)) {
                (Some(_), _) => {
                    rebinds.push((f.name.clone(), snapshot_target(&f.name), false));
                    placeholder.clone()
                }
                (None, Some(fetched)) => fetched.clone(),
                (None, None) => bundle.file(&f.name),
            };
            mounts.push(Mount::Bind {
                source,
                target: snapshot_target(&f.name),
                writable: false,
            });
        }
        let mut lazy_disks = Vec::new();
        if !lazy.files.is_empty() {
            let files: Vec<Arc<LazyFile>> = lazy.files.values().cloned().collect();
            lazy_disks = files.iter().filter(|f| f.writable()).cloned().collect();
            let socket = serve(files, &rs.run_dir, lazy.log.clone())?;
            mounts.push(Mount::Fuse {
                target: LAZY.into(),
                socket,
            });
            for (name, target, writable) in rebinds {
                mounts.push(Mount::Rebind {
                    source: Path::new(LAZY).join(name),
                    target,
                    writable,
                });
            }
        }
        let spec = VmSpec {
            kernel: placeholder.clone(),
            initramfs: Some(placeholder),
            cmdline: Vec::new(),
            disks,
            vcpus: info.vcpus,
            memory_mib: info.memory_mib,
            vsock: info.vsock_spec(),
            net: rs.net.clone(),
            // A bundle never holds a VM on an attached tap (Shape::check_snapshot).
            tap: None,
            console_log: rs.console_log.clone(),
            run_dir: rs.run_dir.clone(),
        };
        Ok(Self {
            info,
            spec,
            mounts,
            lazy_disks,
        })
    }

    /// Whether the memory file is served lazily.
    pub fn lazy_memory(&self) -> bool {
        self.mounts.iter().any(|m| matches!(m, Mount::Fuse { .. }))
            && self.info.memory_file().is_some_and(|name| {
                self.mounts
                    .iter()
                    .any(|m| matches!(m, Mount::Rebind { target, .. } if *target == snapshot_target(name)))
            })
    }

    /// The host file bound at `/vm/snapshot/<name>`: the bundle's, or a fetched state file.
    pub fn source(&self, name: &str) -> Option<&Path> {
        let target = snapshot_target(name);
        self.mounts.iter().find_map(|m| match m {
            Mount::Bind { source, target: t, .. } if *t == target => Some(source.as_path()),
            _ => None,
        })
    }

    /// Binds `source` at `/vm/snapshot/<name>` instead of the bundle's own file.
    pub fn replace(&mut self, name: &str, source: PathBuf) {
        let target = snapshot_target(name);
        for m in &mut self.mounts {
            if let Mount::Bind {
                source: s, target: t, ..
            } = m
                && *t == target
            {
                *s = source.clone();
            }
        }
    }

    /// The shape of the restored VM, for snapshotting it again. A lazily served disk is the
    /// backing file of its [`LazyFile`], which a snapshot completes first.
    pub fn shape(&self) -> Shape {
        let mut shape = Shape::of(&self.spec, self.info.vmm.clone());
        for (n, d) in shape.disks.iter_mut().enumerate() {
            if let Some(f) = self.lazy_disks.iter().find(|f| f.name() == bundle::disk_file(n)) {
                d.path = f.backing_path().to_path_buf();
            }
        }
        shape.lazy = self.lazy_disks.clone();
        shape
    }
}

/// The lazily served files of a restore.
#[derive(Default)]
struct Lazy {
    /// Memory and disks, served through FUSE.
    files: BTreeMap<String, Arc<LazyFile>>,
    /// State files, fetched in full (and verified) into the scratch directory.
    state: BTreeMap<String, PathBuf>,
    log: Option<Log>,
}

impl Lazy {
    fn open(
        index: &LazyIndex,
        source: Arc<dyn ChunkSource>,
        names: &[&FileInfo],
        scratch: &Path,
        run_dir: &Path,
    ) -> Result<Self> {
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(run_dir.join("lazy.log"))?;
        let log: Log = Arc::new(Mutex::new(Box::new(log_file)));
        let mut lazy = Lazy {
            log: Some(log.clone()),
            ..Lazy::default()
        };
        for f in names {
            let entry = &index.files[&f.name];
            let backing = scratch.join(format!("lazy-{}", f.name));
            let file = LazyFile::new(
                &f.name,
                entry,
                index.chunk_size,
                f.role == Role::Disk,
                &backing,
                source.clone(),
                log.clone(),
            )?;
            if f.role == Role::State {
                // The VMM reads state files whole before anything runs: fetch them now.
                file.ensure_all()
                    .map_err(|e| Error::Snapshot(format!("fetching {}: {e}", f.name)))?;
                lazy.state.insert(f.name.clone(), backing);
            } else {
                lazy.files.insert(f.name.clone(), Arc::new(file));
            }
        }
        Ok(lazy)
    }
}

#[cfg(target_os = "linux")]
fn serve(files: Vec<Arc<LazyFile>>, run_dir: &Path, log: Option<Log>) -> Result<PathBuf> {
    let fs = crate::lazy::fuse::Fs::new(
        files,
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    );
    let log = log.expect("a lazy restore has a log");
    Ok(crate::lazy::server::listen(run_dir, fs, log)?)
}

#[cfg(not(target_os = "linux"))]
fn serve(_files: Vec<Arc<LazyFile>>, _run_dir: &Path, _log: Option<Log>) -> Result<PathBuf> {
    Err(Error::Unsupported("lazy restore outside Linux"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::tests::{expect, info};

    /// A bundle matching `bundle::tests::info()`: a 64 MiB memory, a read-only 4 KiB disk
    /// (not captured) and a captured 8 KiB one.
    fn bundle() -> (tempfile::TempDir, SnapshotBundle) {
        let dir = tempfile::tempdir().unwrap();
        bundle::write_info(dir.path(), &info()).unwrap();
        std::fs::write(dir.path().join("vmstate"), b"state").unwrap();
        std::fs::File::create(dir.path().join("memory"))
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
        std::fs::write(dir.path().join("disk-1"), vec![7u8; 8192]).unwrap();
        let b = SnapshotBundle {
            dir: dir.path().to_path_buf(),
        };
        (dir, b)
    }

    fn spec(run: &Path, disks: Vec<RestoreDisk>) -> RestoreSpec {
        RestoreSpec {
            disks,
            console_log: run.join("console.log"),
            run_dir: run.to_path_buf(),
            net: None,
            chunks: None,
            scratch_dir: None,
        }
    }

    #[test]
    fn host_disks_must_match_the_recorded_size_and_captured_disks_are_copied() {
        let (dir, b) = bundle();
        let run = tempfile::tempdir().unwrap();
        let host = dir.path().join("ro.img");
        std::fs::write(&host, vec![0u8; 4096]).unwrap();
        let r = Restore::prepare(
            &b,
            &spec(run.path(), vec![RestoreDisk::Host(host.clone()), RestoreDisk::Captured]),
            &expect(),
        )
        .unwrap();
        assert_eq!(r.spec.disks[0].path, host);
        assert!(r.spec.disks[0].read_only);
        assert_eq!(r.spec.disks[1].path, run.path().join("disk-1"));
        assert_eq!(std::fs::read(&r.spec.disks[1].path).unwrap(), vec![7u8; 8192]);
        assert!(!r.spec.disks[1].read_only);
        let targets: Vec<_> = r.mounts.iter().map(|m| m.target().to_path_buf()).collect();
        assert_eq!(
            targets,
            [
                PathBuf::from("/vm/snapshot/vmstate"),
                PathBuf::from("/vm/snapshot/memory")
            ]
        );
        assert!(!r.lazy_memory());

        std::fs::write(&host, vec![0u8; 1]).unwrap();
        let run2 = tempfile::tempdir().unwrap();
        let err = Restore::prepare(
            &b,
            &spec(
                run2.path(),
                vec![RestoreDisk::Host(host.clone()), RestoreDisk::Captured],
            ),
            &expect(),
        );
        assert!(matches!(err, Err(Error::Snapshot(m)) if m.contains("disk 0")));
        let err = Restore::prepare(
            &b,
            &spec(run2.path(), vec![RestoreDisk::Captured, RestoreDisk::Captured]),
            &expect(),
        );
        assert!(matches!(err, Err(Error::Snapshot(m)) if m.contains("not captured")));
        let err = Restore::prepare(&b, &spec(run2.path(), vec![RestoreDisk::Captured]), &expect());
        assert!(matches!(err, Err(Error::Snapshot(m)) if m.contains("2 disks")));
    }

    #[test]
    fn a_writable_disk_never_comes_from_a_host_file() {
        let (dir, b) = bundle();
        let run = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro.img");
        std::fs::write(&ro, vec![0u8; 4096]).unwrap();
        let shared = dir.path().join("base.img");
        std::fs::write(&shared, vec![0u8; 8192]).unwrap();
        let err = Restore::prepare(
            &b,
            &spec(run.path(), vec![RestoreDisk::Host(ro), RestoreDisk::Host(shared)]),
            &expect(),
        );
        assert!(
            matches!(&err, Err(Error::Snapshot(m)) if m.contains("disk 1 is writable")),
            "{:?}",
            err.err()
        );
    }

    #[test]
    fn an_incomplete_bundle_needs_a_lazy_index_and_a_source() {
        let (dir, b) = bundle();
        std::fs::remove_file(dir.path().join("memory")).unwrap();
        let run = tempfile::tempdir().unwrap();
        let host = dir.path().join("ro.img");
        std::fs::write(&host, vec![0u8; 4096]).unwrap();
        let err = Restore::prepare(
            &b,
            &spec(run.path(), vec![RestoreDisk::Host(host), RestoreDisk::Captured]),
            &expect(),
        );
        assert!(
            matches!(&err, Err(Error::Snapshot(m)) if m.contains("lazy index")),
            "{:?}",
            err.err()
        );
    }

    fn shape(run: &Path) -> Shape {
        Shape {
            vmm: info().vmm,
            vcpus: 1,
            memory_mib: 64,
            vsock: None,
            net: false,
            attached: false,
            disks: Vec::new(),
            run_dir: run.to_path_buf(),
            lazy: Vec::new(),
        }
    }

    #[test]
    fn a_vm_on_an_attached_tap_is_never_snapshotted() {
        let run = tempfile::tempdir().unwrap();
        assert!(shape(run.path()).check_snapshot().is_ok());
        let attached = Shape {
            attached: true,
            ..shape(run.path())
        };
        assert!(matches!(attached.check_snapshot(), Err(Error::Unsupported(_))));
    }

    #[test]
    fn a_snapshot_directory_swapped_for_a_symlink_is_never_read() {
        let run = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        std::fs::create_dir(run.path().join("sock")).unwrap();
        let s = shape(run.path());
        let made = s.vmm_dir().unwrap();
        // The VMM swaps its directory for a link to a host directory holding the right names.
        std::fs::write(host.path().join("vmstate"), b"host secret").unwrap();
        std::fs::write(host.path().join("memory"), b"host secret").unwrap();
        std::fs::remove_dir(run.path().join("sock/snapshot")).unwrap();
        std::os::unix::fs::symlink(host.path(), run.path().join("sock/snapshot")).unwrap();
        let dest = run.path().join("bundle");
        bundle::prepare_dest(&dest).unwrap();
        let err = s.finish(crate::bundle::tests::FC, &dest, made);
        assert!(
            matches!(&err, Err(Error::Snapshot(m)) if m.contains("replaced")),
            "{:?}",
            err.err()
        );
        assert_eq!(std::fs::read(host.path().join("vmstate")).unwrap(), b"host secret");
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0);
    }

    #[test]
    fn finish_collects_the_vmms_files() {
        let run = tempfile::tempdir().unwrap();
        std::fs::create_dir(run.path().join("sock")).unwrap();
        let s = shape(run.path());
        let made = s.vmm_dir().unwrap();
        std::fs::write(run.path().join("sock/snapshot/vmstate"), b"state").unwrap();
        std::fs::File::create(run.path().join("sock/snapshot/memory"))
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
        let dest = run.path().join("bundle");
        bundle::prepare_dest(&dest).unwrap();
        let b = s.finish(crate::bundle::tests::FC, &dest, made).unwrap();
        let i = b.info().unwrap();
        assert_eq!(i.files.len(), 2);
        assert_eq!(std::fs::read(dest.join("vmstate")).unwrap(), b"state");
        assert!(!run.path().join("snapshot-taken").exists());
    }

    #[test]
    fn a_network_must_match_the_snapshot() {
        let (dir, b) = bundle();
        let run = tempfile::tempdir().unwrap();
        let host = dir.path().join("ro.img");
        std::fs::write(&host, vec![0u8; 4096]).unwrap();
        let mut rs = spec(run.path(), vec![RestoreDisk::Host(host), RestoreDisk::Captured]);
        rs.net = Some(crate::NetSpec::default());
        assert!(matches!(Restore::prepare(&b, &rs, &expect()), Err(Error::Snapshot(m)) if m.contains("NIC")));
    }
}
