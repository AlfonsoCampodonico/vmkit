//! Finding the VMM binaries and checking their versions (kiln spec §4.1).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};

/// A `major.minor.patch` version; missing parts are 0.
pub(crate) type Version = (u32, u32, u32);

/// `$env` if set, else the first executable `name` on `PATH`.
pub(crate) fn find(name: &'static str, env: &'static str) -> Result<PathBuf> {
    if let Some(p) = std::env::var_os(env).filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        return if is_executable(&p) {
            Ok(p)
        } else {
            Err(Error::BinaryNotFound { binary: name, env })
        };
    }
    std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|dir| dir.join(name))
        .find(|p| is_executable(p))
        .ok_or(Error::BinaryNotFound { binary: name, env })
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The first `v<digits>[.<digits>...]` token of `text`.
pub(crate) fn parse_version(text: &str) -> Option<Version> {
    let token = text.split_whitespace().find_map(|t| {
        t.strip_prefix('v')
            .filter(|r| r.starts_with(|c: char| c.is_ascii_digit()))
    })?;
    let mut parts = token.split('.').map(|p| {
        p.split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|d| d.parse().ok())
    });
    let major = parts.next()??;
    let minor = parts.next().flatten().unwrap_or(0);
    let patch = parts.next().flatten().unwrap_or(0);
    Some((major, minor, patch))
}

fn show(v: Version) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// Runs `<binary> --version` and refuses anything older than `min`.
pub(crate) fn check_version(path: &Path, name: &'static str, min: Version) -> Result<Version> {
    let out = Command::new(path).arg("--version").output()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let found = parse_version(&text).ok_or_else(|| Error::VersionUnknown {
        binary: name,
        output: text.clone(),
    })?;
    if found < min {
        return Err(Error::VersionTooOld {
            binary: name,
            found: show(found),
            min: show(min),
        });
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_vmm_version_formats() {
        assert_eq!(
            parse_version("Firecracker v1.17.0\n\nSupported snapshot data format versions: v8.0.0"),
            Some((1, 17, 0))
        );
        assert_eq!(
            parse_version("cloud-hypervisor v53.0\nMigration Protocol Versions: 0"),
            Some((53, 0, 0))
        );
        assert_eq!(parse_version("cloud-hypervisor v54.1-dirty"), Some((54, 1, 0)));
        assert_eq!(parse_version("no version here"), None);
        assert_eq!(parse_version("cloud-hypervisor version v53.0"), Some((53, 0, 0)));
    }

    #[test]
    fn env_override_must_be_executable() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fc");
        std::fs::write(&fake, "#!/bin/sh\necho 'Firecracker v1.2.0'\n").unwrap();
        let err = check_version(&fake, "firecracker", (1, 17, 0));
        assert!(err.is_err(), "not executable yet");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = check_version(&fake, "firecracker", (1, 17, 0)).unwrap_err();
        assert!(matches!(err, Error::VersionTooOld { .. }), "{err}");
        assert_eq!(check_version(&fake, "firecracker", (1, 2, 0)).unwrap(), (1, 2, 0));
    }
}
