//! The library's end of a sandbox's FUSE mount: it waits on `<run_dir>/lazy.sock` for the
//! helper to hand over the mount's `/dev/fuse` descriptor ([`crate::sandbox::Mount::Fuse`]),
//! then serves the files. The socket is in the run directory, outside `<run_dir>/sock`, so the
//! VMM can never reach it.

use std::io::{self, IoSliceMut, Write};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};

use super::fuse::{Fs, serve};

/// How long the helper may take to mount and hand over the descriptor.
const HANDOVER: Duration = Duration::from_secs(60);
/// Worker threads per mount: the VMM's vCPU and I/O threads fault in parallel.
const WORKERS: usize = 4;

/// A socket file's identity, from `lstat`.
fn socket_id(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path)?;
    Ok((m.dev(), m.ino()))
}

/// `/dev/fuse` is character device 10:229.
fn is_fuse_device(fd: &OwnedFd) -> io::Result<bool> {
    let st = rustix::fs::fstat(fd)?;
    let kind = rustix::fs::FileType::from_raw_mode(st.st_mode);
    Ok(kind == rustix::fs::FileType::CharacterDevice
        && rustix::fs::major(st.st_rdev) == 10
        && rustix::fs::minor(st.st_rdev) == 229)
}

/// Receives one descriptor sent with `SCM_RIGHTS` on `stream`.
fn receive_fd(stream: &std::os::unix::net::UnixStream) -> io::Result<OwnedFd> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut byte = [0u8; 1];
    recvmsg(
        stream,
        &mut [IoSliceMut::new(&mut byte)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut fds: Vec<OwnedFd> = Vec::new();
    for msg in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = msg {
            fds.extend(received);
        }
    }
    match <[OwnedFd; 1]>::try_from(fds) {
        Ok([fd]) => Ok(fd),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected exactly one descriptor",
        )),
    }
}

/// Starts waiting for the helper on `<run_dir>/lazy.sock`; returns the socket's path for the
/// [`crate::sandbox::Mount::Fuse`]. Once a valid descriptor arrives `fs` is served until the
/// mount goes away with the sandbox. Anything else (a timeout, a descriptor that is not
/// `/dev/fuse`) is reported in `log` and serves nothing, so the sandbox's mount fails or hangs
/// no one but itself.
pub(crate) fn listen(run_dir: &Path, fs: Fs, log: super::file::Log) -> io::Result<PathBuf> {
    let path = run_dir.join("lazy.sock");
    match std::fs::remove_file(&path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(&path)?;
    let ours = socket_id(&path)?;
    listener.set_nonblocking(true)?;
    let fs = Arc::new(fs);
    let socket = path.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + HANDOVER;
        let result = loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    break receive_fd(&stream);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the sandbox never mounted its lazy files",
                    ));
                }
                Err(e) => break Err(e),
            }
        };
        // Only our own socket: a later restore into the same run directory may have bound a
        // new one at this path by now.
        if socket_id(&socket).ok() == Some(ours) {
            let _ = std::fs::remove_file(&socket);
        }
        let failure = match result {
            Ok(fd) => match is_fuse_device(&fd) {
                Ok(true) => {
                    serve(fd, fs, WORKERS);
                    return;
                }
                Ok(false) => "the descriptor received is not /dev/fuse".to_string(),
                Err(e) => e.to_string(),
            },
            Err(e) => e.to_string(),
        };
        if let Ok(mut log) = log.lock() {
            let _ = writeln!(log, "vmkit lazy: {failure}");
        }
    });
    Ok(path)
}
