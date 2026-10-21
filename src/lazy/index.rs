//! `lazy.json`, vmkit's lazy index (format 1, lazy-restore design §6.2): which files of a
//! bundle are not in its directory but served in content-addressed chunks, and their chunks.
//!
//! The index comes from untrusted input (kiln writes it from a pulled snapshot), so its
//! bounds are checked before anything is fetched.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::process::open_vmm_file;

/// The index's file name in a bundle directory.
pub const LAZY_FILE: &str = "lazy.json";
/// The version of `lazy.json` this vmkit reads.
pub const LAZY_VERSION: u32 = 1;
/// The smallest and largest chunk sizes (powers of two).
pub const MIN_CHUNK: u64 = 64 << 10;
pub const MAX_CHUNK: u64 = 16 << 20;
/// The largest file an index may describe.
pub const MAX_FILE: u64 = 1 << 40;
/// The largest `lazy.json` read.
const MAX_INDEX: u64 = 16 << 20;

/// A bundle's lazily served files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LazyIndex {
    pub version: u32,
    pub chunk_size: u64,
    pub files: BTreeMap<String, IndexedFile>,
}

/// One file: its size and its chunks. `chunks[i]` covers bytes
/// `[i * chunk_size, min((i + 1) * chunk_size, size))`; `None` means all zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexedFile {
    pub size: u64,
    pub chunks: Vec<Option<String>>,
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Snapshot(format!("{LAZY_FILE}: {}", msg.into()))
}

/// The 32 bytes of `sha256:<64 lowercase hex>`, or `None`.
pub(crate) fn parse_digest(d: &str) -> Option<[u8; 32]> {
    let hex = d.strip_prefix("sha256:")?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// `sha256:<hex>` of `bytes`.
pub fn digest_of(bytes: &[u8]) -> String {
    let sum = Sha256::digest(bytes);
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for b in sum.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl IndexedFile {
    /// The length of chunk `i`: `chunk_size`, except for a short last chunk.
    pub fn chunk_len(&self, chunk_size: u64, i: usize) -> u64 {
        let start = i as u64 * chunk_size;
        chunk_size.min(self.size - start)
    }
}

impl LazyIndex {
    /// Reads `<dir>/lazy.json`, if there is one.
    pub fn read(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(LAZY_FILE);
        let file = match open_vmm_file(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(bad(format!("{}: {e}", path.display()))),
        };
        let mut bytes = Vec::new();
        file.take(MAX_INDEX + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_INDEX {
            return Err(bad(format!("over {MAX_INDEX} bytes")));
        }
        let index: Self = serde_json::from_slice(&bytes).map_err(|e| bad(e.to_string()))?;
        index.check()?;
        Ok(Some(index))
    }

    /// The bounds of design §5.4: the version, the chunk size, and that every file's chunks
    /// cover exactly its size with well-formed digests.
    pub fn check(&self) -> Result<()> {
        if self.version != LAZY_VERSION {
            return Err(bad(format!("version {} is not supported", self.version)));
        }
        if !self.chunk_size.is_power_of_two() || !(MIN_CHUNK..=MAX_CHUNK).contains(&self.chunk_size) {
            return Err(bad(format!(
                "chunk size {} is not a power of two from {MIN_CHUNK} to {MAX_CHUNK}",
                self.chunk_size
            )));
        }
        for (name, f) in &self.files {
            if f.size > MAX_FILE {
                return Err(bad(format!("{name} is over {MAX_FILE} bytes")));
            }
            if f.chunks.len() as u64 != f.size.div_ceil(self.chunk_size) {
                return Err(bad(format!(
                    "{name} has {} chunks for {} bytes",
                    f.chunks.len(),
                    f.size
                )));
            }
            if let Some(d) = f.chunks.iter().flatten().find(|d| parse_digest(d).is_none()) {
                return Err(bad(format!(
                    "{name} names the chunk {d:?}, which is not a sha256 digest"
                )));
            }
        }
        Ok(())
    }
}

/// Splits `file` into chunks of `chunk_size`, giving each non-zero chunk to `sink` with its
/// digest, and returns the file's index entry. Zero chunks are `None` and never reach `sink`.
pub fn split(file: &mut dyn Read, chunk_size: u64, sink: &mut dyn FnMut(&str, &[u8])) -> std::io::Result<IndexedFile> {
    let mut chunks = Vec::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; chunk_size as usize];
    loop {
        let mut n = 0;
        while n < buf.len() {
            match file.read(&mut buf[n..])? {
                0 => break,
                k => n += k,
            }
        }
        if n == 0 {
            break;
        }
        size += n as u64;
        let chunk = &buf[..n];
        if chunk.iter().all(|&b| b == 0) {
            chunks.push(None);
        } else {
            let d = digest_of(chunk);
            sink(&d, chunk);
            chunks.push(Some(d));
        }
        if n < buf.len() {
            break;
        }
    }
    Ok(IndexedFile { size, chunks })
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn index(size: u64, chunks: Vec<Option<String>>) -> LazyIndex {
        LazyIndex {
            version: 1,
            chunk_size: MIN_CHUNK,
            files: [("memory".to_string(), IndexedFile { size, chunks })].into(),
        }
    }

    #[test]
    fn digests_must_be_sha256() {
        assert!(index(MIN_CHUNK, vec![Some(D.into())]).check().is_ok());
        for d in ["sha512:00", "sha256:ABCDEF", "md5:x", &D.to_uppercase(), &D[..70]] {
            assert!(index(MIN_CHUNK, vec![Some(d.into())]).check().is_err(), "{d}");
        }
        assert_eq!(parse_digest(D).unwrap()[..2], [0x01, 0x23]);
    }

    #[test]
    fn chunk_counts_must_cover_the_size() {
        assert!(index(MIN_CHUNK + 1, vec![None, None]).check().is_ok());
        assert!(index(MIN_CHUNK + 1, vec![None]).check().is_err());
        assert!(index(MIN_CHUNK, vec![None, None]).check().is_err());
        assert!(index(0, vec![]).check().is_ok());
    }

    #[test]
    fn chunk_sizes_and_versions_are_bounded() {
        let mut i = index(0, vec![]);
        for bad in [0, 4096, MIN_CHUNK + 1, MAX_CHUNK * 2] {
            i.chunk_size = bad;
            assert!(i.check().is_err(), "{bad}");
        }
        let mut i = index(0, vec![]);
        i.version = 2;
        assert!(i.check().is_err());
        let i = index(MAX_FILE + 1, vec![]);
        assert!(i.check().is_err());
    }

    #[test]
    fn unknown_keys_are_refused_and_a_missing_index_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(LazyIndex::read(dir.path()).unwrap(), None);
        std::fs::write(
            dir.path().join(LAZY_FILE),
            r#"{"version":1,"chunk_size":65536,"files":{},"x":1}"#,
        )
        .unwrap();
        assert!(LazyIndex::read(dir.path()).is_err());
        std::fs::write(
            dir.path().join(LAZY_FILE),
            r#"{"version":1,"chunk_size":65536,"files":{}}"#,
        )
        .unwrap();
        assert!(LazyIndex::read(dir.path()).unwrap().is_some());
    }

    #[test]
    fn split_skips_zero_chunks_and_keeps_a_short_last_one() {
        let mut data = vec![0u8; 3 * MIN_CHUNK as usize + 10];
        data[MIN_CHUNK as usize] = 1;
        data[3 * MIN_CHUNK as usize + 9] = 2;
        let mut seen = Vec::new();
        let f = split(&mut &data[..], MIN_CHUNK, &mut |d, bytes| {
            seen.push((d.to_string(), bytes.len()))
        })
        .unwrap();
        assert_eq!(f.size, data.len() as u64);
        assert_eq!(f.chunks.len(), 4);
        assert_eq!(f.chunks[0], None);
        assert_eq!(f.chunks[2], None);
        assert_eq!(
            f.chunks[1].as_deref(),
            Some(digest_of(&data[MIN_CHUNK as usize..2 * MIN_CHUNK as usize]).as_str())
        );
        assert_eq!(
            seen.iter().map(|(_, n)| *n).collect::<Vec<_>>(),
            [MIN_CHUNK as usize, 10]
        );
        assert_eq!(f.chunk_len(MIN_CHUNK, 3), 10);
    }
}
