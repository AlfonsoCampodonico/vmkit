//! Lazy restore below the VMM (lazy-restore design §6): bundle files fetched in verified,
//! content-addressed chunks on demand, for both backends.

/// Where chunks come from. Implementations may cache; vmkit verifies every chunk they return
/// (its SHA-256 and length), whatever the source.
pub trait ChunkSource: Send + Sync {
    /// The bytes of the chunk whose SHA-256 is `digest` (`sha256:<hex>`), `size` bytes long.
    fn fetch(&self, digest: &str, size: u64) -> std::io::Result<Vec<u8>>;
}

mod cache;
pub(crate) mod file;
pub(crate) mod fuse;
mod index;
#[cfg(target_os = "linux")]
pub(crate) mod server;

pub use cache::DirCache;
pub use index::{IndexedFile, LAZY_FILE, LAZY_VERSION, LazyIndex, MAX_CHUNK, MIN_CHUNK, digest_of, split};
