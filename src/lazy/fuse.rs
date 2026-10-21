//! The FUSE server that serves lazily fetched files to the VMM (lazy-restore design §6.1).
//!
//! vmkit owns the protocol subset it needs instead of wrapping libfuse: one flat, fixed
//! directory of [`LazyFile`]s, mounted inside the VMM's sandbox. Requests are decoded from
//! bytes and replies encoded to bytes by [`Fs::handle`], which needs no kernel, so the whole
//! protocol is unit-tested; [`serve`] only moves those bytes through `/dev/fuse` (Linux).
//!
//! Layouts follow `include/uapi/linux/fuse.h`. vmkit answers `INIT` with protocol 7.31, so
//! the kernel sends only requests that version knows, in its layouts.
// Reached only through the Linux FUSE server; unit-tested everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;
use std::sync::Arc;

use super::file::LazyFile;

pub(crate) const FUSE_KERNEL_VERSION: u32 = 7;
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 31;
/// The largest write the kernel may send, and so the read buffer (plus headers).
pub(crate) const MAX_WRITE: u32 = 128 << 10;
#[cfg(target_os = "linux")]
pub(crate) const BUFFER: usize = MAX_WRITE as usize + 4096;
/// The root directory's inode.
const ROOT: u64 = 1;
/// How long the kernel may cache names and attributes: nothing here ever changes.
const VALID_SECS: u64 = 3600;

// Opcodes.
const LOOKUP: u32 = 1;
const FORGET: u32 = 2;
const GETATTR: u32 = 3;
const SETATTR: u32 = 4;
const OPEN: u32 = 14;
const READ: u32 = 15;
const WRITE: u32 = 16;
const STATFS: u32 = 17;
const RELEASE: u32 = 18;
const FSYNC: u32 = 20;
const FLUSH: u32 = 25;
const INIT: u32 = 26;
const OPENDIR: u32 = 27;
const READDIR: u32 = 28;
const RELEASEDIR: u32 = 29;
const FSYNCDIR: u32 = 30;
const ACCESS: u32 = 34;
const INTERRUPT: u32 = 36;
const DESTROY: u32 = 38;
const BATCH_FORGET: u32 = 42;
const FALLOCATE: u32 = 43;
const LSEEK: u32 = 46;

const FOPEN_KEEP_CACHE: u32 = 1 << 1;
const FUSE_ASYNC_READ: u32 = 1 << 0;
const FUSE_BIG_WRITES: u32 = 1 << 5;
/// `FATTR_SIZE` in a `SETATTR`.
const FATTR_SIZE: u32 = 1 << 3;
const SEEK_DATA: u32 = 3;
const SEEK_HOLE: u32 = 4;
const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
/// `O_ACCMODE` and `O_RDONLY` of an `OPEN`'s flags.
const O_ACCMODE: u32 = 3;
const O_RDONLY: u32 = 0;
const O_TRUNC: u32 = 0o1000;

/// `struct fuse_in_header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
}

const IN_HEADER: usize = 40;
const OUT_HEADER: usize = 16;

/// Little-endian fields of a request body, bounds-checked.
struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.bytes.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at.min(self.bytes.len())..]
    }
}

pub(crate) fn decode_header(req: &[u8]) -> Option<InHeader> {
    let mut f = Fields::new(req);
    let h = InHeader {
        len: f.u32()?,
        opcode: f.u32()?,
        unique: f.u64()?,
        nodeid: f.u64()?,
    };
    if (h.len as usize) < IN_HEADER || h.len as usize > req.len() {
        return None;
    }
    Some(h)
}

/// A reply: `struct fuse_out_header` and a body, or an error.
fn reply(unique: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(OUT_HEADER + body.len());
    out.extend_from_slice(&((OUT_HEADER + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&unique.to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn error(unique: u64, errno: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(OUT_HEADER);
    out.extend_from_slice(&(OUT_HEADER as u32).to_le_bytes());
    out.extend_from_slice(&(-errno).to_le_bytes());
    out.extend_from_slice(&unique.to_le_bytes());
    out
}

fn errno_of(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

/// A flat directory of lazy files: inode 1 is the root, files are 2, 3, ... in name order.
pub(crate) struct Fs {
    files: Vec<Arc<LazyFile>>,
    uid: u32,
    gid: u32,
}

impl Fs {
    pub fn new(mut files: Vec<Arc<LazyFile>>, uid: u32, gid: u32) -> Self {
        files.sort_by(|a, b| a.name().cmp(b.name()));
        Self { files, uid, gid }
    }

    fn file(&self, ino: u64) -> Option<&Arc<LazyFile>> {
        ino.checked_sub(2).and_then(|i| self.files.get(i as usize))
    }

    /// `struct fuse_attr`.
    fn attr(&self, ino: u64) -> Option<Vec<u8>> {
        let (size, mode, nlink) = if ino == ROOT {
            (0, S_IFDIR | 0o500, 2)
        } else {
            let f = self.file(ino)?;
            (f.size(), S_IFREG | if f.writable() { 0o600 } else { 0o400 }, 1)
        };
        let mut a = Vec::with_capacity(88);
        a.extend_from_slice(&ino.to_le_bytes());
        a.extend_from_slice(&size.to_le_bytes());
        a.extend_from_slice(&size.div_ceil(512).to_le_bytes());
        a.extend_from_slice(&[0u8; 24]); // atime, mtime, ctime
        a.extend_from_slice(&[0u8; 12]); // their nanoseconds
        a.extend_from_slice(&mode.to_le_bytes());
        a.extend_from_slice(&(nlink as u32).to_le_bytes());
        a.extend_from_slice(&self.uid.to_le_bytes());
        a.extend_from_slice(&self.gid.to_le_bytes());
        a.extend_from_slice(&0u32.to_le_bytes()); // rdev
        a.extend_from_slice(&4096u32.to_le_bytes()); // blksize
        a.extend_from_slice(&0u32.to_le_bytes()); // flags
        Some(a)
    }

    /// `struct fuse_attr_out`.
    fn attr_out(&self, ino: u64) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(104);
        out.extend_from_slice(&VALID_SECS.to_le_bytes());
        out.extend_from_slice(&[0u8; 8]); // attr_valid_nsec, dummy
        out.extend(self.attr(ino)?);
        Some(out)
    }

    /// Handles one request; `None` for those that take no reply (`FORGET`, `INTERRUPT`).
    pub fn handle(&self, req: &[u8]) -> Option<Vec<u8>> {
        let Some(h) = decode_header(req) else {
            // Without a header there is no `unique` to answer to.
            return None;
        };
        let body = &req[IN_HEADER..h.len as usize];
        match self.dispatch(&h, body) {
            Ok(Some(b)) => Some(reply(h.unique, &b)),
            Ok(None) => None,
            Err(errno) => Some(error(h.unique, errno)),
        }
    }

    fn dispatch(&self, h: &InHeader, body: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        let mut f = Fields::new(body);
        let short = libc::EINVAL;
        let regular = |ino: u64| self.file(ino).ok_or(libc::ENOENT);
        Ok(Some(match h.opcode {
            INIT => {
                let major = f.u32().ok_or(short)?;
                let _minor = f.u32().ok_or(short)?;
                let max_readahead = f.u32().ok_or(short)?;
                let flags = f.u32().ok_or(short)?;
                if major != FUSE_KERNEL_VERSION {
                    return Err(libc::EPROTO);
                }
                let mut out = Vec::with_capacity(64);
                out.extend_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
                out.extend_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
                out.extend_from_slice(&max_readahead.min(MAX_WRITE).to_le_bytes());
                out.extend_from_slice(&(flags & (FUSE_ASYNC_READ | FUSE_BIG_WRITES)).to_le_bytes());
                out.extend_from_slice(&16u16.to_le_bytes()); // max_background
                out.extend_from_slice(&12u16.to_le_bytes()); // congestion_threshold
                out.extend_from_slice(&MAX_WRITE.to_le_bytes());
                out.extend_from_slice(&1u32.to_le_bytes()); // time_gran
                out.resize(64, 0);
                out
            }
            LOOKUP => {
                if h.nodeid != ROOT {
                    return Err(libc::ENOTDIR);
                }
                let name = f.rest().split(|&b| b == 0).next().unwrap_or_default();
                let i = self
                    .files
                    .iter()
                    .position(|x| x.name().as_bytes() == name)
                    .ok_or(libc::ENOENT)?;
                let ino = i as u64 + 2;
                let mut out = Vec::with_capacity(128);
                out.extend_from_slice(&ino.to_le_bytes());
                out.extend_from_slice(&0u64.to_le_bytes()); // generation
                out.extend_from_slice(&VALID_SECS.to_le_bytes());
                out.extend_from_slice(&VALID_SECS.to_le_bytes());
                out.extend_from_slice(&[0u8; 8]);
                out.extend(self.attr(ino).expect("a listed file"));
                out
            }
            FORGET | BATCH_FORGET | INTERRUPT => return Ok(None),
            GETATTR => self.attr_out(h.nodeid).ok_or(libc::ENOENT)?,
            SETATTR => {
                let valid = f.u32().ok_or(short)?;
                f.take(4).ok_or(short)?;
                let _fh = f.u64().ok_or(short)?;
                let size = f.u64().ok_or(short)?;
                let file = regular(h.nodeid)?;
                // Times and modes are not kept; a size change would resize a disk or memory.
                if valid & FATTR_SIZE != 0 && size != file.size() {
                    return Err(libc::EPERM);
                }
                self.attr_out(h.nodeid).expect("a listed file")
            }
            OPEN => {
                let flags = f.u32().ok_or(short)?;
                let file = regular(h.nodeid)?;
                if (flags & O_ACCMODE != O_RDONLY && !file.writable()) || flags & O_TRUNC != 0 {
                    return Err(libc::EACCES);
                }
                let mut out = Vec::with_capacity(16);
                out.extend_from_slice(&0u64.to_le_bytes()); // fh
                out.extend_from_slice(&FOPEN_KEEP_CACHE.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out
            }
            OPENDIR => {
                if h.nodeid != ROOT {
                    return Err(libc::ENOTDIR);
                }
                vec![0u8; 16]
            }
            READ => {
                let _fh = f.u64().ok_or(short)?;
                let offset = f.u64().ok_or(short)?;
                let size = f.u32().ok_or(short)?;
                regular(h.nodeid)?
                    .read_at(offset, size.min(MAX_WRITE))
                    .map_err(|e| errno_of(&e))?
            }
            WRITE => {
                let _fh = f.u64().ok_or(short)?;
                let offset = f.u64().ok_or(short)?;
                let size = f.u32().ok_or(short)?;
                f.take(4 + 8 + 4 + 4).ok_or(short)?; // write_flags, lock_owner, flags, padding
                let data = f.take(size as usize).ok_or(short)?;
                regular(h.nodeid)?.write_at(offset, data).map_err(|e| errno_of(&e))?;
                let mut out = size.to_le_bytes().to_vec();
                out.extend_from_slice(&0u32.to_le_bytes());
                out
            }
            READDIR => {
                if h.nodeid != ROOT {
                    return Err(libc::ENOTDIR);
                }
                let _fh = f.u64().ok_or(short)?;
                let offset = f.u64().ok_or(short)?;
                let size = f.u32().ok_or(short)? as usize;
                let mut entries: Vec<(u64, u32, &[u8])> = vec![(ROOT, DT_DIR, b"."), (ROOT, DT_DIR, b"..")];
                entries.extend(
                    self.files
                        .iter()
                        .enumerate()
                        .map(|(i, x)| (i as u64 + 2, DT_REG, x.name().as_bytes())),
                );
                let mut out = Vec::new();
                for (k, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
                    // `struct fuse_dirent`, padded to 8 bytes; `off` is the next entry's.
                    let len = (24 + name.len()).next_multiple_of(8);
                    if out.len() + len > size {
                        break;
                    }
                    out.extend_from_slice(&ino.to_le_bytes());
                    out.extend_from_slice(&(k as u64 + 1).to_le_bytes());
                    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
                    out.extend_from_slice(&kind.to_le_bytes());
                    out.extend_from_slice(name);
                    out.resize(out.len().next_multiple_of(8), 0);
                }
                out
            }
            RELEASE | RELEASEDIR | FLUSH | FSYNCDIR | ACCESS => Vec::new(),
            FSYNC => {
                regular(h.nodeid)?.sync().map_err(|e| errno_of(&e))?;
                Vec::new()
            }
            STATFS => {
                // `struct fuse_kstatfs`: a full, read-only-looking filesystem.
                let mut out = vec![0u8; 80];
                out[40..44].copy_from_slice(&4096u32.to_le_bytes()); // bsize
                out[44..48].copy_from_slice(&255u32.to_le_bytes()); // namelen
                out[48..52].copy_from_slice(&4096u32.to_le_bytes()); // frsize
                out
            }
            LSEEK => {
                let _fh = f.u64().ok_or(short)?;
                let offset = f.u64().ok_or(short)?;
                let whence = f.u32().ok_or(short)?;
                let file = regular(h.nodeid)?;
                let at = match whence {
                    SEEK_DATA | SEEK_HOLE => file.seek(offset, whence == SEEK_DATA).map_err(|e| errno_of(&e))?,
                    // SEEK_SET, SEEK_CUR and SEEK_END the kernel answers itself.
                    _ => return Err(libc::EINVAL),
                };
                at.to_le_bytes().to_vec()
            }
            FALLOCATE => {
                let _fh = f.u64().ok_or(short)?;
                let offset = f.u64().ok_or(short)?;
                let length = f.u64().ok_or(short)?;
                let mode = f.u32().ok_or(short)?;
                let file = regular(h.nodeid)?;
                fallocate(file, mode, offset, length).map_err(|e| errno_of(&e))?;
                Vec::new()
            }
            DESTROY => Vec::new(),
            _ => return Err(libc::ENOSYS),
        }))
    }
}

#[cfg(target_os = "linux")]
fn fallocate(file: &LazyFile, mode: u32, offset: u64, len: u64) -> io::Result<()> {
    file.fallocate(mode, offset, len)
}

#[cfg(not(target_os = "linux"))]
fn fallocate(_file: &LazyFile, _mode: u32, _offset: u64, _len: u64) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
}

/// Serves `fs` on the `/dev/fuse` descriptor `dev` with `threads` workers, until the
/// filesystem is unmounted (the sandbox's mount namespace went away).
#[cfg(target_os = "linux")]
pub(crate) fn serve(dev: std::os::fd::OwnedFd, fs: Arc<Fs>, threads: usize) -> Vec<std::thread::JoinHandle<()>> {
    let dev = Arc::new(dev);
    (0..threads)
        .map(|_| {
            let (dev, fs) = (dev.clone(), fs.clone());
            std::thread::spawn(move || {
                let mut buf = vec![0u8; BUFFER];
                loop {
                    let n = match rustix::io::read(&*dev, &mut buf) {
                        Ok(n) => n,
                        // An interrupted read, or a request the kernel withdrew: try again.
                        Err(rustix::io::Errno::INTR | rustix::io::Errno::NOENT | rustix::io::Errno::AGAIN) => continue,
                        // ENODEV: unmounted. Anything else ends this worker as well.
                        Err(_) => return,
                    };
                    if let Some(out) = fs.handle(&buf[..n]) {
                        // ENOENT: the request was interrupted and its reply is not wanted.
                        let _ = rustix::io::write(&*dev, &out);
                    }
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lazy::file::tests::{CS, lazy, null_log, sample};

    fn request(opcode: u32, nodeid: u64, body: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&((IN_HEADER + body.len()) as u32).to_le_bytes());
        r.extend_from_slice(&opcode.to_le_bytes());
        r.extend_from_slice(&77u64.to_le_bytes());
        r.extend_from_slice(&nodeid.to_le_bytes());
        r.extend_from_slice(&[0u8; 16]); // uid, gid, pid, extlen, padding
        r.extend_from_slice(body);
        r
    }

    /// The error and body of a reply to request 77.
    fn answer(out: Vec<u8>) -> (i32, Vec<u8>) {
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()) as usize, out.len());
        assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 77);
        (-i32::from_le_bytes(out[4..8].try_into().unwrap()), out[16..].to_vec())
    }

    fn le64(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
    }

    fn le32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    struct T {
        _dir: tempfile::TempDir,
        fs: Fs,
        data: Vec<u8>,
    }

    fn fs(writable: bool) -> T {
        let dir = tempfile::tempdir().unwrap();
        let data = sample();
        let (_, f, _) = lazy(&data, writable, dir.path(), null_log());
        T {
            fs: Fs::new(vec![Arc::new(f)], 1000, 1000),
            _dir: dir,
            data,
        }
    }

    fn rw_body(offset: u64, size: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&offset.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&[0u8; 20]);
        b
    }

    #[test]
    fn init_answers_with_7_31_and_bounded_writes() {
        let t = fs(false);
        let mut body = Vec::new();
        for v in [7u32, 41, 1 << 20, 0xffff_ffff] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.resize(64, 0);
        let (err, out) = answer(t.fs.handle(&request(INIT, 0, &body)).unwrap());
        assert_eq!(err, 0);
        assert_eq!(out.len(), 64);
        assert_eq!((le32(&out, 0), le32(&out, 4)), (7, 31));
        assert_eq!(le32(&out, 8), MAX_WRITE, "readahead capped");
        assert_eq!(le32(&out, 12), FUSE_ASYNC_READ | FUSE_BIG_WRITES);
        assert_eq!(le32(&out, 20), MAX_WRITE);
        body[0] = 8;
        assert_eq!(answer(t.fs.handle(&request(INIT, 0, &body)).unwrap()).0, libc::EPROTO);
    }

    #[test]
    fn lookup_getattr_and_read_go_through_the_lazy_file() {
        let t = fs(false);
        let (err, out) = answer(t.fs.handle(&request(LOOKUP, ROOT, b"f\0")).unwrap());
        assert_eq!(err, 0);
        assert_eq!(out.len(), 128);
        let ino = le64(&out, 0);
        assert_eq!(ino, 2);
        assert_eq!(le64(&out, 40 + 8), t.data.len() as u64, "the full size");
        assert_eq!(
            le32(&out, 40 + 60),
            S_IFREG | 0o400,
            "memory and read-only disks are 0400"
        );
        assert_eq!(
            answer(t.fs.handle(&request(LOOKUP, ROOT, b"g\0")).unwrap()).0,
            libc::ENOENT
        );
        let (_, attr) = answer(t.fs.handle(&request(GETATTR, ino, &[0u8; 16])).unwrap());
        assert_eq!(attr.len(), 104);
        assert_eq!(le64(&attr, 16 + 8), t.data.len() as u64);
        let (err, bytes) = answer(t.fs.handle(&request(READ, ino, &rw_body(CS - 3, 6))).unwrap());
        assert_eq!(err, 0);
        assert_eq!(bytes, &t.data[CS as usize - 3..CS as usize + 3]);
    }

    #[test]
    fn writes_to_a_read_only_file_are_refused() {
        let t = fs(false);
        let open = |flags: u32| {
            answer(
                t.fs.handle(&request(OPEN, 2, &[flags.to_le_bytes(), [0; 4]].concat()))
                    .unwrap(),
            )
        };
        assert_eq!(open(libc::O_RDWR as u32).0, libc::EACCES);
        assert_eq!(open(libc::O_WRONLY as u32).0, libc::EACCES);
        let (err, out) = open(libc::O_RDONLY as u32);
        assert_eq!(err, 0);
        assert_eq!(le32(&out, 8), FOPEN_KEEP_CACHE);
        let mut w = rw_body(0, 4);
        w.extend_from_slice(b"abcd");
        assert_eq!(answer(t.fs.handle(&request(WRITE, 2, &w)).unwrap()).0, libc::EBADF);
    }

    #[test]
    fn writes_to_a_writable_file_persist() {
        let t = fs(true);
        let mut w = rw_body(10, 4);
        w.extend_from_slice(b"abcd");
        let (err, out) = answer(t.fs.handle(&request(WRITE, 2, &w)).unwrap());
        assert_eq!((err, le32(&out, 0)), (0, 4));
        let (_, bytes) = answer(t.fs.handle(&request(READ, 2, &rw_body(8, 8))).unwrap());
        assert_eq!(bytes, [&t.data[8..10], b"abcd", &t.data[14..16]].concat());
        let mut set = vec![0u8; 88];
        set[0..4].copy_from_slice(&FATTR_SIZE.to_le_bytes());
        set[16..24].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            answer(t.fs.handle(&request(SETATTR, 2, &set)).unwrap()).0,
            libc::EPERM,
            "no resizing"
        );
    }

    #[test]
    fn lseek_data_skips_zero_chunks() {
        let t = fs(false);
        let seek = |offset: u64, whence: u32| {
            let mut b = Vec::new();
            b.extend_from_slice(&0u64.to_le_bytes());
            b.extend_from_slice(&offset.to_le_bytes());
            b.extend_from_slice(&whence.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            answer(t.fs.handle(&request(LSEEK, 2, &b)).unwrap())
        };
        assert_eq!(le64(&seek(0, SEEK_HOLE).1, 0), CS);
        assert_eq!(le64(&seek(CS, SEEK_DATA).1, 0), 2 * CS);
        assert_eq!(seek(0, 0).0, libc::EINVAL);
    }

    #[test]
    fn readdir_lists_the_files_and_resumes_at_an_offset() {
        let t = fs(false);
        let (_, all) = answer(t.fs.handle(&request(READDIR, ROOT, &rw_body(0, 4096))).unwrap());
        // ".", ".." and "f": 32 + 32 + 32 bytes.
        assert_eq!(all.len(), 96);
        assert_eq!(&all[64 + 24..64 + 25], b"f");
        assert_eq!(le32(&all, 64 + 20), DT_REG);
        let (_, rest) = answer(t.fs.handle(&request(READDIR, ROOT, &rw_body(2, 4096))).unwrap());
        assert_eq!(rest, all[64..]);
        let (_, none) = answer(t.fs.handle(&request(READDIR, ROOT, &rw_body(3, 4096))).unwrap());
        assert!(none.is_empty());
    }

    #[test]
    fn unknown_opcodes_are_enosys_and_forgets_get_no_reply() {
        let t = fs(false);
        assert_eq!(answer(t.fs.handle(&request(9999, 2, &[])).unwrap()).0, libc::ENOSYS);
        assert_eq!(
            answer(t.fs.handle(&request(10, ROOT, b"f\0")).unwrap()).0,
            libc::ENOSYS,
            "UNLINK"
        );
        assert!(t.fs.handle(&request(FORGET, 2, &1u64.to_le_bytes())).is_none());
        assert!(t.fs.handle(&request(INTERRUPT, 0, &77u64.to_le_bytes())).is_none());
    }

    #[test]
    fn truncated_requests_are_einval_and_garbage_is_ignored() {
        let t = fs(false);
        assert_eq!(
            answer(t.fs.handle(&request(READ, 2, &[0u8; 4])).unwrap()).0,
            libc::EINVAL
        );
        assert!(t.fs.handle(&[1, 2, 3]).is_none());
        let mut lying = request(GETATTR, 2, &[0u8; 16]);
        lying[0..4].copy_from_slice(&9999u32.to_le_bytes());
        assert!(t.fs.handle(&lying).is_none(), "a length past the buffer");
    }
}
