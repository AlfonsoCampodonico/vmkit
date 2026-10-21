//! Snapshot bundles on disk (lazy-restore design §4.2): `bundle.json`, the VMM's own files
//! and the captured disks, and the checks a bundle passes before anything restores it.
//!
//! A bundle is untrusted. It may come from a registry, and the files in it were written by a
//! VMM, which a hostile guest may have compromised. So every file is opened without following
//! symlinks and must be regular, names are fixed by the backend, and sizes must agree with
//! what `bundle.json` claims.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::process::open_vmm_file;
use crate::spec::{SnapshotBundle, VsockSpec};

/// The version of `bundle.json` this vmkit reads and writes.
pub const BUNDLE_VERSION: u32 = 1;
/// The bundle's description, in its directory.
pub const BUNDLE_FILE: &str = "bundle.json";
/// The largest `bundle.json` read: it lists a handful of files and disks.
const MAX_BUNDLE_JSON: u64 = 64 << 10;
/// The largest state file accepted (VMM state is kilobytes; this bounds what a hostile lazy
/// index can make a restore fetch before the VMM starts).
pub const MAX_STATE: u64 = 64 << 20;

/// What a bundle holds, from its `bundle.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleInfo {
    pub version: u32,
    /// The VMM that wrote the snapshot; only the same VMM and version restore it.
    pub vmm: VmmId,
    /// `std::env::consts::ARCH` of the host that took the snapshot.
    pub arch: String,
    pub vcpus: u8,
    pub memory_mib: u32,
    /// Whether the VM had a NIC; a restore must give it one exactly when it did.
    pub net: bool,
    pub vsock: Option<BundleVsock>,
    /// The VM's disks, in order.
    pub disks: Vec<DiskInfo>,
    /// Every file in the bundle besides `bundle.json`.
    pub files: Vec<FileInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmmId {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleVsock {
    pub guest_cid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskInfo {
    pub read_only: bool,
    /// The disk's size in bytes when the snapshot was taken.
    pub size: u64,
    /// Whether the bundle holds the disk's content as `disk-<n>` (writable disks always do).
    pub captured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileInfo {
    pub name: String,
    pub role: Role,
}

/// What a bundle file is for: the lazy layer fetches state files whole, and serves memory
/// and disks on demand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    State,
    Memory,
    Disk,
}

/// The files a backend writes for a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Layout {
    pub state: &'static [&'static str],
    pub memory: &'static str,
}

/// What the restoring backend is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expect<'a> {
    pub vmm: &'a str,
    pub version: &'a str,
    pub arch: &'a str,
    pub layout: Layout,
}

/// The name of captured disk `n` in a bundle.
pub fn disk_file(n: usize) -> String {
    format!("disk-{n}")
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Snapshot(msg.into())
}

impl BundleInfo {
    /// `bundle.json`'s bytes: canonical JSON with sorted keys.
    pub fn to_json(&self) -> Vec<u8> {
        // A `Value` map is sorted by key, whatever the order of the struct's fields.
        let value = serde_json::to_value(self).expect("a bundle serialises");
        let mut out = serde_json::to_vec_pretty(&value).expect("a value serialises");
        out.push(b'\n');
        out
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| bad(format!("{BUNDLE_FILE}: {e}")))
    }

    /// The file holding guest memory.
    pub fn memory_file(&self) -> Option<&str> {
        self.files
            .iter()
            .find(|f| f.role == Role::Memory)
            .map(|f| f.name.as_str())
    }

    /// Checks that a backend can restore this bundle, and that the files `size_of` reports
    /// agree with it. `size_of` opens or looks up a file by name (never following a symlink).
    pub(crate) fn check(&self, expect: &Expect, size_of: &mut dyn FnMut(&str) -> Result<u64>) -> Result<()> {
        if self.version != BUNDLE_VERSION {
            return Err(bad(format!(
                "bundle version {} is not supported (this vmkit reads {BUNDLE_VERSION})",
                self.version
            )));
        }
        if self.vmm.name != expect.vmm || self.vmm.version != expect.version {
            return Err(bad(format!(
                "the snapshot was taken by {} {}, and only that VMM restores it (this is {} {})",
                self.vmm.name, self.vmm.version, expect.vmm, expect.version
            )));
        }
        if self.arch != expect.arch {
            return Err(bad(format!("the snapshot is for {}, not {}", self.arch, expect.arch)));
        }
        if self.vcpus == 0 || self.memory_mib < 64 {
            return Err(bad("at least 1 vCPU and 64 MiB of memory are required"));
        }
        let mut expected: Vec<(String, Role)> = expect
            .layout
            .state
            .iter()
            .map(|n| (n.to_string(), Role::State))
            .collect();
        expected.push((expect.layout.memory.to_string(), Role::Memory));
        for (n, d) in self.disks.iter().enumerate() {
            if d.captured && d.read_only {
                return Err(bad(format!(
                    "disk {n} is read-only, and only writable disks are captured"
                )));
            }
            if !d.captured && !d.read_only {
                return Err(bad(format!(
                    "disk {n} is writable, and writable disks are always captured"
                )));
            }
            if d.captured {
                expected.push((disk_file(n), Role::Disk));
            }
        }
        let listed: BTreeSet<(String, Role)> = self.files.iter().map(|f| (f.name.clone(), f.role)).collect();
        if listed.len() != self.files.len() || listed != expected.iter().cloned().collect() {
            return Err(bad(format!(
                "the bundle lists the files {:?}, but a {} snapshot with these disks has {:?}",
                self.files.iter().map(|f| &f.name).collect::<Vec<_>>(),
                expect.vmm,
                expected.iter().map(|(n, _)| n).collect::<Vec<_>>()
            )));
        }
        let memory = u64::from(self.memory_mib) << 20;
        for (name, role) in &expected {
            let size = size_of(name)?;
            let want = match role {
                Role::State if size > MAX_STATE => {
                    return Err(bad(format!(
                        "{name} is {size} bytes, over the {MAX_STATE} a state file may have"
                    )));
                }
                Role::State => continue,
                Role::Memory => memory,
                Role::Disk => {
                    let n: usize = name["disk-".len()..].parse().expect("a name this function made");
                    self.disks[n].size
                }
            };
            if size != want {
                return Err(bad(format!("{name} is {size} bytes, but the bundle says {want}")));
            }
        }
        Ok(())
    }

    /// The vsock device as a spec.
    pub fn vsock_spec(&self) -> Option<VsockSpec> {
        self.vsock.map(|v| VsockSpec { guest_cid: v.guest_cid })
    }
}

impl SnapshotBundle {
    /// Reads `<dir>/bundle.json`.
    pub fn info(&self) -> Result<BundleInfo> {
        let path = self.dir.join(BUNDLE_FILE);
        let file = open_vmm_file(&path).map_err(|e| bad(format!("{}: {e}", path.display())))?;
        let mut bytes = Vec::new();
        file.take(MAX_BUNDLE_JSON + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BUNDLE_JSON {
            return Err(bad(format!("{} is over {MAX_BUNDLE_JSON} bytes", path.display())));
        }
        BundleInfo::from_json(&bytes)
    }

    /// The path of `name` in the bundle.
    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The size of the regular file `name`, opened without following a symlink.
    pub(crate) fn local_size(&self, name: &str) -> Result<u64> {
        let path = self.file(name);
        let file = open_vmm_file(&path).map_err(|e| bad(format!("{}: {e}", path.display())))?;
        Ok(file.metadata()?.len())
    }
}

/// Makes `dest` an empty directory for a snapshot: created when missing, refused when it
/// holds anything.
pub(crate) fn prepare_dest(dest: &Path) -> Result<()> {
    match std::fs::read_dir(dest) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(bad(format!("{} is not empty", dest.display())));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(std::fs::create_dir_all(dest)?),
        Err(e) => Err(e.into()),
    }
}

/// Moves `src`, a file the VMM wrote, to `<dest>/<name>`. A symlink or anything but a
/// regular file is refused, so a compromised VMM cannot make vmkit read a host file into a
/// snapshot. Across filesystems the file is copied (sparsely) and the source removed.
pub(crate) fn take_file(src: &Path, dest: &Path, name: &str) -> Result<()> {
    let file = open_vmm_file(src).map_err(|e| bad(format!("{}: {e}", src.display())))?;
    let target = dest.join(name);
    match std::fs::rename(src, &target) {
        Ok(()) => {
            // The rename moved whatever `src` named at that moment: check it is still the
            // file just opened (a swap in between would put another inode in the bundle).
            use std::os::unix::fs::MetadataExt;
            let moved = std::fs::symlink_metadata(&target)?;
            let opened = file.metadata()?;
            if !moved.is_file() || moved.ino() != opened.ino() || moved.dev() != opened.dev() {
                let _ = std::fs::remove_file(&target);
                return Err(bad(format!("{} changed while it was moved", src.display())));
            }
        }
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            copy_sparse(&file, &target)?;
            std::fs::remove_file(src)?;
        }
        Err(e) => return Err(e.into()),
    }
    File::open(&target)?.sync_all()?;
    Ok(())
}

/// Copies `src` to a new file `dst`, keeping holes: only the data extents are copied.
pub(crate) fn copy_sparse(src: &File, dst: &Path) -> Result<()> {
    let len = src.metadata()?.len();
    // A copy left by an earlier, failed restore into the same directory.
    match std::fs::remove_file(dst) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dst)?;
    let mut src = src.try_clone()?;
    let mut pos = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    while pos < len {
        let Some(data) = seek_data(&src, pos)?.filter(|&d| d < len) else {
            break;
        };
        let hole = seek_hole(&src, data)?.min(len);
        src.seek(SeekFrom::Start(data))?;
        out.seek(SeekFrom::Start(data))?;
        let mut left = hole - data;
        while left > 0 {
            let n = buf.len().min(left as usize);
            src.read_exact(&mut buf[..n])?;
            out.write_all(&buf[..n])?;
            left -= n as u64;
        }
        pos = hole;
    }
    out.set_len(len)?;
    out.sync_all()?;
    Ok(())
}

/// The next data offset at or after `pos`, or `None` when only a hole remains.
fn seek_data(f: &File, pos: u64) -> io::Result<Option<u64>> {
    match lseek(f, pos, libc::SEEK_DATA) {
        Ok(p) => Ok(Some(p)),
        Err(e) if e.raw_os_error() == Some(libc::ENXIO) => Ok(None),
        // A filesystem without SEEK_DATA: everything is data.
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Ok(Some(pos)),
        Err(e) => Err(e),
    }
}

fn seek_hole(f: &File, pos: u64) -> io::Result<u64> {
    match lseek(f, pos, libc::SEEK_HOLE) {
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => f.metadata().map(|m| m.len()),
        r => r,
    }
}

#[cfg(target_os = "linux")]
fn lseek(f: &File, pos: u64, whence: i32) -> io::Result<u64> {
    let whence = match whence {
        libc::SEEK_DATA => rustix::fs::SeekFrom::Data(pos),
        _ => rustix::fs::SeekFrom::Hole(pos),
    };
    Ok(rustix::fs::seek(f, whence)?)
}

/// Elsewhere (macOS, for unit tests) the whole file is data.
#[cfg(not(target_os = "linux"))]
fn lseek(f: &File, pos: u64, whence: i32) -> io::Result<u64> {
    if whence == libc::SEEK_DATA {
        if pos >= f.metadata()?.len() {
            return Err(io::Error::from_raw_os_error(libc::ENXIO));
        }
        Ok(pos)
    } else {
        f.metadata().map(|m| m.len())
    }
}

/// Writes `bundle.json` into `dest` atomically, the last file of a snapshot.
pub(crate) fn write_info(dest: &Path, info: &BundleInfo) -> Result<()> {
    let tmp = dest.join(".bundle.json.tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    f.write_all(&info.to_json())?;
    f.sync_all()?;
    std::fs::rename(&tmp, dest.join(BUNDLE_FILE))?;
    File::open(dest)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const FC: Layout = Layout {
        state: &["vmstate"],
        memory: "memory",
    };

    pub(crate) fn expect() -> Expect<'static> {
        Expect {
            vmm: "firecracker",
            version: "1.17.0",
            arch: "aarch64",
            layout: FC,
        }
    }

    pub(crate) fn info() -> BundleInfo {
        BundleInfo {
            version: 1,
            vmm: VmmId {
                name: "firecracker".into(),
                version: "1.17.0".into(),
            },
            arch: "aarch64".into(),
            vcpus: 1,
            memory_mib: 64,
            net: false,
            vsock: Some(BundleVsock { guest_cid: 3 }),
            disks: vec![
                DiskInfo {
                    read_only: true,
                    size: 4096,
                    captured: false,
                },
                DiskInfo {
                    read_only: false,
                    size: 8192,
                    captured: true,
                },
            ],
            files: vec![
                FileInfo {
                    name: "vmstate".into(),
                    role: Role::State,
                },
                FileInfo {
                    name: "memory".into(),
                    role: Role::Memory,
                },
                FileInfo {
                    name: "disk-1".into(),
                    role: Role::Disk,
                },
            ],
        }
    }

    /// Sizes that agree with `info()`.
    fn sizes(name: &str) -> Result<u64> {
        Ok(match name {
            "memory" => 64 << 20,
            "disk-1" => 8192,
            _ => 100,
        })
    }

    fn check(i: &BundleInfo) -> Result<()> {
        i.check(&expect(), &mut sizes)
    }

    fn snapshot_err(r: Result<()>) -> String {
        match r {
            Err(Error::Snapshot(m)) => m,
            other => panic!("expected a snapshot error, got {other:?}"),
        }
    }

    #[test]
    fn bundle_json_round_trips_with_sorted_keys() {
        let json = info().to_json();
        assert_eq!(BundleInfo::from_json(&json).unwrap(), info());
        let text = String::from_utf8(json).unwrap();
        let keys: Vec<usize> = [
            "\"arch\"",
            "\"disks\"",
            "\"files\"",
            "\"memory_mib\"",
            "\"net\"",
            "\"vcpus\"",
            "\"version\"",
            "\"vmm\"",
            "\"vsock\"",
        ]
        .iter()
        .map(|k| text.find(k).unwrap())
        .collect();
        assert!(keys.windows(2).all(|w| w[0] < w[1]), "{text}");
        assert!(check(&info()).is_ok());
    }

    #[test]
    fn unknown_keys_and_versions_are_refused() {
        let mut v = serde_json::to_value(info()).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(BundleInfo::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
        let mut i = info();
        i.version = 2;
        assert!(snapshot_err(check(&i)).contains("version 2"));
    }

    #[test]
    fn only_the_same_vmm_version_and_arch_restore() {
        let mut i = info();
        i.vmm.name = "cloud-hypervisor".into();
        assert!(snapshot_err(check(&i)).contains("only that VMM"));
        let mut i = info();
        i.vmm.version = "1.16.0".into();
        assert!(snapshot_err(check(&i)).contains("only that VMM"));
        let mut i = info();
        i.arch = "x86_64".into();
        assert!(snapshot_err(check(&i)).contains("x86_64"));
    }

    #[test]
    fn the_file_set_must_match_the_vmm() {
        let mut i = info();
        i.files.push(FileInfo {
            name: "../../etc/passwd".into(),
            role: Role::State,
        });
        assert!(snapshot_err(check(&i)).contains("lists the files"));
        let mut i = info();
        i.files.remove(2);
        assert!(snapshot_err(check(&i)).contains("lists the files"));
        let mut i = info();
        i.files[1].role = Role::State;
        assert!(snapshot_err(check(&i)).contains("lists the files"));
        let mut i = info();
        i.files.push(i.files[0].clone());
        assert!(snapshot_err(check(&i)).contains("lists the files"));
    }

    #[test]
    fn memory_and_disk_sizes_are_checked() {
        let short = |name: &str| -> Result<u64> {
            Ok(if name == "memory" {
                (64 << 20) - 4096
            } else {
                sizes(name)?
            })
        };
        let mut short = short;
        assert!(snapshot_err(info().check(&expect(), &mut short)).contains("memory"));
        let mut big_disk = |name: &str| -> Result<u64> { Ok(if name == "disk-1" { 1 } else { sizes(name)? }) };
        assert!(snapshot_err(info().check(&expect(), &mut big_disk)).contains("disk-1"));
    }

    #[test]
    fn state_files_are_bounded() {
        let mut huge = |name: &str| -> Result<u64> { Ok(if name == "vmstate" { MAX_STATE + 1 } else { sizes(name)? }) };
        assert!(snapshot_err(info().check(&expect(), &mut huge)).contains("state file"));
    }

    #[test]
    fn captured_read_only_and_uncaptured_writable_disks_are_refused() {
        let mut i = info();
        i.disks[0].captured = true;
        assert!(snapshot_err(check(&i)).contains("read-only"));
        let mut i = info();
        i.disks[1].captured = false;
        assert!(snapshot_err(check(&i)).contains("always captured"));
    }

    #[test]
    fn symlinked_and_non_regular_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let b = SnapshotBundle {
            dir: dir.path().to_path_buf(),
        };
        std::fs::write(dir.path().join("target"), b"secret").unwrap();
        std::os::unix::fs::symlink(dir.path().join("target"), dir.path().join("memory")).unwrap();
        assert!(matches!(b.local_size("memory"), Err(Error::Snapshot(_))));
        std::fs::create_dir(dir.path().join("vmstate")).unwrap();
        assert!(matches!(b.local_size("vmstate"), Err(Error::Snapshot(_))));
        std::os::unix::fs::symlink(dir.path().join("target"), dir.path().join(BUNDLE_FILE)).unwrap();
        assert!(matches!(b.info(), Err(Error::Snapshot(_))));
        assert_eq!(b.local_size("target").unwrap(), 6);
    }

    #[test]
    fn take_file_refuses_a_symlink_planted_by_the_vmm() {
        let vmm = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        std::fs::write(vmm.path().join("host-secret"), b"secret").unwrap();
        std::os::unix::fs::symlink(vmm.path().join("host-secret"), vmm.path().join("memory")).unwrap();
        assert!(take_file(&vmm.path().join("memory"), dest.path(), "memory").is_err());
        assert!(!dest.path().join("memory").exists());
        std::fs::write(vmm.path().join("vmstate"), b"state").unwrap();
        take_file(&vmm.path().join("vmstate"), dest.path(), "vmstate").unwrap();
        assert_eq!(std::fs::read(dest.path().join("vmstate")).unwrap(), b"state");
        assert!(!vmm.path().join("vmstate").exists());
    }

    #[test]
    fn copy_sparse_keeps_content_and_holes() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let f = File::create(&src).unwrap();
        f.set_len(64 << 20).unwrap();
        let mut f = OpenOptions::new().write(true).open(&src).unwrap();
        f.seek(SeekFrom::Start(32 << 20)).unwrap();
        f.write_all(b"data in the middle").unwrap();
        drop(f);
        let dst = dir.path().join("dst");
        copy_sparse(&File::open(&src).unwrap(), &dst).unwrap();
        assert_eq!(std::fs::read(&src).unwrap(), std::fs::read(&dst).unwrap());
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let blocks = std::fs::metadata(&dst).unwrap().blocks();
            assert!(blocks * 512 < 8 << 20, "the copy is sparse ({blocks} blocks)");
        }
    }

    #[test]
    fn dest_must_be_empty_or_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("a/b");
        prepare_dest(&missing).unwrap();
        assert!(missing.is_dir());
        prepare_dest(&missing).unwrap();
        std::fs::write(missing.join("x"), b"").unwrap();
        assert!(matches!(prepare_dest(&missing), Err(Error::Snapshot(_))));
    }

    #[test]
    fn write_info_leaves_only_bundle_json() {
        let dir = tempfile::tempdir().unwrap();
        write_info(dir.path(), &info()).unwrap();
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [BUNDLE_FILE]);
        let b = SnapshotBundle {
            dir: dir.path().to_path_buf(),
        };
        assert_eq!(b.info().unwrap(), info());
    }
}
