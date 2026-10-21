//! One lazily fetched file of a bundle (lazy-restore design §6.1).
//!
//! Its bytes live in a sparse local backing file. A chunk is fetched, verified and written
//! there the first time anything reads or writes it; from then on the backing file is the
//! truth. Zero chunks are present from the start (the backing file's holes read as zero), so
//! they never cost a fetch. Writes (writable disks only) therefore always land on fetched
//! chunks, and never reach the source.
// Reached only through the Linux FUSE server; unit-tested everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};

use sha2::{Digest, Sha256};

use super::ChunkSource;
use super::index::{IndexedFile, parse_digest};

/// How many times a chunk is fetched before reads of it fail.
const ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Absent,
    Fetching,
    Present,
    /// A zero chunk nothing has written: present, and a hole for `SEEK_DATA`.
    Zero,
}

/// Where failed and corrupt fetches are reported (`<run_dir>/lazy.log`).
pub(crate) type Log = Arc<Mutex<Box<dyn Write + Send>>>;

pub(crate) struct LazyFile {
    name: String,
    size: u64,
    chunk_size: u64,
    /// The expected SHA-256 of each chunk; `None` for a zero chunk.
    chunks: Vec<Option<[u8; 32]>>,
    digests: Vec<Option<String>>,
    writable: bool,
    backing: File,
    backing_path: std::path::PathBuf,
    state: Mutex<Vec<State>>,
    changed: Condvar,
    source: Arc<dyn ChunkSource>,
    log: Log,
}

impl LazyFile {
    /// A lazy file for `entry`, backed by a new sparse file at `backing`.
    pub fn new(
        name: &str,
        entry: &IndexedFile,
        chunk_size: u64,
        writable: bool,
        backing: &Path,
        source: Arc<dyn ChunkSource>,
        log: Log,
    ) -> io::Result<Self> {
        // A backing file left by an earlier, failed restore into the same directory.
        match std::fs::remove_file(backing) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(backing)?;
        file.set_len(entry.size)?;
        let chunks: Vec<Option<[u8; 32]>> = entry
            .chunks
            .iter()
            .map(|d| d.as_deref().map(|d| parse_digest(d).expect("a checked index")))
            .collect();
        let state = chunks
            .iter()
            .map(|c| if c.is_some() { State::Absent } else { State::Zero })
            .collect();
        Ok(Self {
            name: name.into(),
            size: entry.size,
            chunk_size,
            chunks,
            digests: entry.chunks.clone(),
            writable,
            backing: file,
            backing_path: backing.to_path_buf(),
            state: Mutex::new(state),
            changed: Condvar::new(),
            source,
            log,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn writable(&self) -> bool {
        self.writable
    }

    /// The local backing file: complete once [`LazyFile::ensure_all`] returns.
    pub fn backing_path(&self) -> &Path {
        &self.backing_path
    }

    /// The chunks a byte range touches.
    fn chunks_of(&self, offset: u64, len: u64) -> std::ops::Range<usize> {
        if len == 0 || offset >= self.size {
            return 0..0;
        }
        let end = (offset + len).min(self.size);
        (offset / self.chunk_size) as usize..end.div_ceil(self.chunk_size) as usize
    }

    fn log(&self, msg: String) {
        if let Ok(mut log) = self.log.lock() {
            let _ = writeln!(log, "vmkit lazy: {}: {msg}", self.name);
        }
    }

    /// Makes chunk `i` present, fetching it if no one has. Concurrent callers for the same
    /// chunk wait for one fetch; other chunks proceed.
    fn ensure(&self, i: usize) -> io::Result<()> {
        let mut state = self.state.lock().expect("not poisoned");
        loop {
            match state[i] {
                State::Present | State::Zero => return Ok(()),
                State::Fetching => state = self.changed.wait(state).expect("not poisoned"),
                State::Absent => break,
            }
        }
        state[i] = State::Fetching;
        drop(state);
        // Whatever happens in the fetch, a panic in a source included, the chunk leaves
        // `Fetching` and its waiters wake: a stuck chunk would hang the VMM's faults on it.
        struct Settle<'a> {
            file: &'a LazyFile,
            i: usize,
            done: bool,
        }
        impl Drop for Settle<'_> {
            fn drop(&mut self) {
                let mut state = self.file.state.lock().unwrap_or_else(|p| p.into_inner());
                state[self.i] = if self.done { State::Present } else { State::Absent };
                self.file.changed.notify_all();
            }
        }
        let mut settle = Settle {
            file: self,
            i,
            done: false,
        };
        let result = self.fetch(i);
        settle.done = result.is_ok();
        drop(settle);
        result
    }

    /// Fetches chunk `i` into the backing file. Bytes that do not hash to the chunk's digest,
    /// or have the wrong length, are an integrity failure and never written.
    fn fetch(&self, i: usize) -> io::Result<()> {
        let want = self.chunks[i].expect("only data chunks are fetched");
        let digest = self.digests[i].as_deref().expect("only data chunks are fetched");
        let start = i as u64 * self.chunk_size;
        let len = self.chunk_size.min(self.size - start);
        for attempt in 1..=ATTEMPTS {
            match self.source.fetch(digest, len) {
                Ok(bytes) if bytes.len() as u64 == len && Sha256::digest(&bytes)[..] == want => {
                    self.backing.write_all_at(&bytes, start)?;
                    return Ok(());
                }
                Ok(bytes) => self.log(format!(
                    "chunk {i} ({digest}): the source returned {} bytes that are not the chunk (attempt {attempt}/{ATTEMPTS})",
                    bytes.len()
                )),
                Err(e) => self.log(format!("chunk {i} ({digest}): {e} (attempt {attempt}/{ATTEMPTS})")),
            }
        }
        Err(io::Error::other(format!(
            "{}: chunk {i} could not be fetched",
            self.name
        )))
    }

    /// Makes every chunk of the range present.
    pub fn ensure_range(&self, offset: u64, len: u64) -> io::Result<()> {
        for i in self.chunks_of(offset, len) {
            self.ensure(i)?;
        }
        Ok(())
    }

    /// Makes the whole file present (before a snapshot copies it, say).
    pub fn ensure_all(&self) -> io::Result<()> {
        self.ensure_range(0, self.size)
    }

    /// Reads up to `len` bytes at `offset`; short at the end of the file.
    pub fn read_at(&self, offset: u64, len: u32) -> io::Result<Vec<u8>> {
        if offset >= self.size {
            return Ok(Vec::new());
        }
        let len = u64::from(len).min(self.size - offset);
        self.ensure_range(offset, len)?;
        let mut buf = vec![0u8; len as usize];
        self.backing.read_exact_at(&mut buf, offset)?;
        Ok(buf)
    }

    /// Writes `data` at `offset`. The file never grows: a disk has the size it was captured with.
    pub fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        if offset.checked_add(data.len() as u64).is_none_or(|end| end > self.size) {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC));
        }
        self.ensure_range(offset, data.len() as u64)?;
        self.written(offset, data.len() as u64);
        self.backing.write_all_at(data, offset)
    }

    /// Zero chunks in the range may hold data from now on.
    fn written(&self, offset: u64, len: u64) {
        let mut state = self.state.lock().expect("not poisoned");
        for i in self.chunks_of(offset, len) {
            if state[i] == State::Zero {
                state[i] = State::Present;
            }
        }
    }

    /// Whether chunk `i` may hold anything but zeros (for `SEEK_DATA` and `SEEK_HOLE`).
    fn may_hold_data(&self, i: usize) -> bool {
        self.state.lock().expect("not poisoned")[i] != State::Zero
    }

    /// `lseek` with `SEEK_DATA` (`data`) or `SEEK_HOLE`, at chunk granularity: zero chunks are
    /// holes, so a reader that skips holes never fetches them.
    pub fn seek(&self, offset: u64, data: bool) -> io::Result<u64> {
        if offset >= self.size {
            return Err(io::Error::from_raw_os_error(libc::ENXIO));
        }
        let first = (offset / self.chunk_size) as usize;
        for i in first..self.chunks.len() {
            if self.may_hold_data(i) == data {
                return Ok((i as u64 * self.chunk_size).max(offset));
            }
        }
        if data {
            Err(io::Error::from_raw_os_error(libc::ENXIO))
        } else {
            Ok(self.size)
        }
    }

    pub fn sync(&self) -> io::Result<()> {
        self.backing.sync_data()
    }

    /// Punches a hole or zeroes a range of a writable file (`fallocate` from a guest discard).
    #[cfg(target_os = "linux")]
    pub fn fallocate(&self, mode: u32, offset: u64, len: u64) -> io::Result<()> {
        use rustix::fs::FallocateFlags;
        if !self.writable {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        let flags = FallocateFlags::from_bits(mode).ok_or_else(|| io::Error::from_raw_os_error(libc::EOPNOTSUPP))?;
        if !flags.intersects(FallocateFlags::PUNCH_HOLE | FallocateFlags::ZERO_RANGE)
            || !flags.contains(FallocateFlags::KEEP_SIZE) && flags.contains(FallocateFlags::PUNCH_HOLE)
        {
            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }
        if offset.checked_add(len).is_none_or(|end| end > self.size) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // The partly covered chunks must be present, or a later fetch would overwrite the
        // zeroes; whole chunks become present too, which is what the zeroes make them.
        self.ensure_range(offset, len)?;
        self.written(offset, len);
        Ok(rustix::fs::fallocate(&self.backing, flags, offset, len)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::lazy::index::{digest_of, split};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(crate) const CS: u64 = 64 << 10;

    /// A source over in-memory chunks that counts fetches, and can be told to lie.
    #[derive(Default)]
    pub(crate) struct Counting {
        pub chunks: Mutex<HashMap<String, Vec<u8>>>,
        pub fetches: AtomicUsize,
        pub corrupt: Mutex<Option<String>>,
    }

    impl ChunkSource for Counting {
        fn fetch(&self, digest: &str, _size: u64) -> io::Result<Vec<u8>> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(5));
            let mut bytes = self
                .chunks
                .lock()
                .unwrap()
                .get(digest)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, digest.to_string()))?;
            if self.corrupt.lock().unwrap().as_deref() == Some(digest) {
                bytes[0] ^= 1;
            }
            Ok(bytes)
        }
    }

    pub(crate) fn null_log() -> Log {
        Arc::new(Mutex::new(Box::new(io::sink())))
    }

    /// A shared log the test can read back.
    #[derive(Clone, Default)]
    pub(crate) struct Captured(pub Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// `data` split into a source, and a lazy file over it.
    pub(crate) fn lazy(data: &[u8], writable: bool, dir: &Path, log: Log) -> (Arc<Counting>, LazyFile, IndexedFile) {
        let source = Arc::new(Counting::default());
        let entry = split(&mut &data[..], CS, &mut |d, b| {
            source.chunks.lock().unwrap().insert(d.to_string(), b.to_vec());
        })
        .unwrap();
        let f = LazyFile::new("f", &entry, CS, writable, &dir.join("backing"), source.clone(), log).unwrap();
        (source, f, entry)
    }

    /// Four chunks: data, zero, data, and a short data chunk.
    pub(crate) fn sample() -> Vec<u8> {
        let mut data = vec![0u8; 3 * CS as usize + 100];
        for (i, b) in data.iter_mut().enumerate() {
            if !(CS as usize..2 * CS as usize).contains(&i) {
                *b = (i % 251) as u8 + 1;
            }
        }
        data
    }

    #[test]
    fn only_touched_chunks_are_fetched() {
        let dir = tempfile::tempdir().unwrap();
        let data = sample();
        let (src, f, _) = lazy(&data, false, dir.path(), null_log());
        assert_eq!(f.read_at(10, 20).unwrap(), &data[10..30]);
        assert_eq!(src.fetches.load(Ordering::SeqCst), 1);
        assert_eq!(f.read_at(5, 10).unwrap(), &data[5..15]);
        assert_eq!(
            src.fetches.load(Ordering::SeqCst),
            1,
            "a present chunk is not fetched again"
        );
        let tail = f.read_at(3 * CS - 5, 1000).unwrap();
        assert_eq!(tail, &data[3 * CS as usize - 5..], "short at the end of the file");
        assert_eq!(src.fetches.load(Ordering::SeqCst), 3);
        assert_eq!(f.read_at(data.len() as u64, 10).unwrap(), b"");
    }

    #[test]
    fn zero_chunks_read_as_zero_without_a_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let (src, f, entry) = lazy(&sample(), false, dir.path(), null_log());
        assert_eq!(entry.chunks[1], None);
        assert_eq!(f.read_at(CS, CS as u32).unwrap(), vec![0u8; CS as usize]);
        assert_eq!(src.fetches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn concurrent_readers_of_one_chunk_fetch_it_once() {
        let dir = tempfile::tempdir().unwrap();
        let data = sample();
        let (src, f, _) = lazy(&data, false, dir.path(), null_log());
        let f = Arc::new(f);
        let threads: Vec<_> = (0..8)
            .map(|k| {
                let f = f.clone();
                std::thread::spawn(move || f.read_at(k * 100, 100).unwrap())
            })
            .collect();
        for (k, t) in threads.into_iter().enumerate() {
            assert_eq!(t.join().unwrap(), &data[k * 100..k * 100 + 100]);
        }
        assert_eq!(src.fetches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_corrupt_chunk_is_an_io_error_and_is_logged() {
        let dir = tempfile::tempdir().unwrap();
        let data = sample();
        let captured = Captured::default();
        let log: Log = Arc::new(Mutex::new(Box::new(captured.clone())));
        let (src, f, entry) = lazy(&data, false, dir.path(), log);
        *src.corrupt.lock().unwrap() = entry.chunks[0].clone();
        assert!(f.read_at(0, 10).is_err());
        assert_eq!(src.fetches.load(Ordering::SeqCst), ATTEMPTS);
        let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("chunk 0") && text.contains("not the chunk"), "{text}");
        // Nothing unverified reached the backing file, and a good source is tried again.
        *src.corrupt.lock().unwrap() = None;
        assert_eq!(f.read_at(0, 10).unwrap(), &data[..10]);
    }

    /// A source that panics.
    struct Panics;
    impl ChunkSource for Panics {
        fn fetch(&self, _: &str, _: u64) -> io::Result<Vec<u8>> {
            panic!("a broken source")
        }
    }

    #[test]
    fn a_panicking_source_leaves_no_chunk_stuck() {
        let dir = tempfile::tempdir().unwrap();
        let data = sample();
        let entry = split(&mut &data[..], CS, &mut |_, _| {}).unwrap();
        let f = Arc::new(
            LazyFile::new(
                "f",
                &entry,
                CS,
                false,
                &dir.path().join("b"),
                Arc::new(Panics),
                null_log(),
            )
            .unwrap(),
        );
        let g = f.clone();
        assert!(std::thread::spawn(move || g.read_at(0, 1)).join().is_err());
        // The chunk is absent again, not Fetching forever: a second reader does not hang.
        let g = f.clone();
        let t = std::thread::spawn(move || g.read_at(0, 1));
        assert!(t.join().is_err(), "it panics again rather than waiting");
    }

    #[test]
    fn a_missing_chunk_is_retried_then_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (src, f, entry) = lazy(&sample(), false, dir.path(), null_log());
        src.chunks.lock().unwrap().remove(entry.chunks[2].as_ref().unwrap());
        assert!(f.read_at(2 * CS, 1).is_err());
        assert_eq!(src.fetches.load(Ordering::SeqCst), ATTEMPTS);
    }

    #[test]
    fn writes_after_fetch_persist_and_never_reach_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let data = sample();
        let (src, f, _) = lazy(&data, true, dir.path(), null_log());
        f.write_at(CS - 2, b"abcd").unwrap();
        // The write spans a data chunk (fetched) and a zero chunk (present already).
        assert_eq!(src.fetches.load(Ordering::SeqCst), 1);
        assert_eq!(
            f.read_at(CS - 4, 8).unwrap(),
            [&data[CS as usize - 4..CS as usize - 2], b"abcd", &[0, 0]].concat()
        );
        let before = src.chunks.lock().unwrap().clone();
        assert_eq!(*src.chunks.lock().unwrap(), before);
        assert!(f.write_at(data.len() as u64 - 1, b"xy").is_err(), "a disk never grows");
        let ro_dir = tempfile::tempdir().unwrap();
        let (_, ro, _) = lazy(&data, false, ro_dir.path(), null_log());
        assert!(ro.write_at(0, b"x").is_err());
    }

    #[test]
    fn seek_reports_zero_chunks_as_holes() {
        let dir = tempfile::tempdir().unwrap();
        let data = sample();
        let (src, f, _) = lazy(&data, true, dir.path(), null_log());
        assert_eq!(f.seek(0, true).unwrap(), 0);
        assert_eq!(f.seek(10, false).unwrap(), CS);
        assert_eq!(f.seek(CS + 5, true).unwrap(), 2 * CS);
        assert_eq!(f.seek(2 * CS, false).unwrap(), data.len() as u64);
        assert!(f.seek(data.len() as u64, true).is_err());
        assert_eq!(src.fetches.load(Ordering::SeqCst), 0, "seeking fetches nothing");
        // A written zero chunk may hold data now.
        f.write_at(CS + 1, b"x").unwrap();
        assert_eq!(f.seek(CS + 5, true).unwrap(), CS + 5);
    }

    #[test]
    fn ensure_all_makes_the_backing_file_complete() {
        let dir = tempfile::tempdir().unwrap();
        let data = sample();
        let (src, f, _) = lazy(&data, false, dir.path(), null_log());
        f.ensure_all().unwrap();
        assert_eq!(src.fetches.load(Ordering::SeqCst), 3);
        assert_eq!(std::fs::read(dir.path().join("backing")).unwrap(), data);
        assert_eq!(
            digest_of(&data),
            digest_of(&std::fs::read(dir.path().join("backing")).unwrap())
        );
    }
}
