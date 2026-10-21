//! A local chunk cache for callers without a store of their own (kiln uses its blob store).

use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use super::ChunkSource;
use super::index::parse_digest;

/// A [`ChunkSource`] that keeps every chunk it fetched, verified, in a directory named by
/// digest, so a later restore of the same snapshot (or one sharing chunks) fetches only what
/// is new. A cached entry is checked again on every read: a damaged cache costs a refetch,
/// never a wrong byte.
pub struct DirCache {
    dir: PathBuf,
    inner: Arc<dyn ChunkSource>,
}

impl DirCache {
    /// Caches `inner`'s chunks in `dir`, which is created if missing.
    pub fn new(dir: impl Into<PathBuf>, inner: Arc<dyn ChunkSource>) -> io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, inner })
    }

    fn path(&self, digest: &str) -> io::Result<PathBuf> {
        if parse_digest(digest).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad digest {digest:?}"),
            ));
        }
        Ok(self.dir.join(&digest["sha256:".len()..]))
    }
}

fn matches(bytes: &[u8], digest: &str, size: u64) -> bool {
    bytes.len() as u64 == size && parse_digest(digest).is_some_and(|d| Sha256::digest(bytes)[..] == d)
}

impl ChunkSource for DirCache {
    fn fetch(&self, digest: &str, size: u64) -> io::Result<Vec<u8>> {
        let path = self.path(digest)?;
        if let Ok(bytes) = std::fs::read(&path)
            && matches(&bytes, digest, size)
        {
            return Ok(bytes);
        }
        let bytes = self.inner.fetch(digest, size)?;
        if matches(&bytes, digest, size) {
            // Written aside and renamed, so a reader never sees half a chunk.
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let tmp = self.dir.join(format!(
                ".tmp-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            std::fs::rename(&tmp, &path)?;
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lazy::file::tests::Counting;
    use crate::lazy::index::digest_of;

    #[test]
    fn a_cached_chunk_is_not_fetched_again_and_a_corrupt_entry_is_refetched() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Arc::new(Counting::default());
        let d = digest_of(b"chunk");
        inner.chunks.lock().unwrap().insert(d.clone(), b"chunk".to_vec());
        let cache = DirCache::new(dir.path().join("c"), inner.clone()).unwrap();
        assert_eq!(cache.fetch(&d, 5).unwrap(), b"chunk");
        assert_eq!(cache.fetch(&d, 5).unwrap(), b"chunk");
        assert_eq!(inner.fetches.load(Ordering::SeqCst), 1);
        std::fs::write(dir.path().join("c").join(&d[7..]), b"chunX").unwrap();
        assert_eq!(cache.fetch(&d, 5).unwrap(), b"chunk");
        assert_eq!(inner.fetches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn bad_chunks_are_never_cached_and_bad_digests_never_name_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Arc::new(Counting::default());
        let d = digest_of(b"chunk");
        inner.chunks.lock().unwrap().insert(d.clone(), b"chunk".to_vec());
        *inner.corrupt.lock().unwrap() = Some(d.clone());
        let cache = DirCache::new(dir.path(), inner.clone()).unwrap();
        cache.fetch(&d, 5).unwrap();
        assert!(!dir.path().join(&d[7..]).exists());
        assert!(cache.fetch("sha256:../../etc/passwd", 5).is_err());
    }
}
