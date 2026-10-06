//! The seccomp filter for sandboxed programs (potter spec §9.4): a deny list of the system
//! calls that change namespaces, mounts, keyrings, the kernel or the clock, applied after
//! `no_new_privs` and right before the program's exec.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
};

/// Refused with `EPERM`.
const DENIED: &[libc::c_long] = &[
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
    libc::SYS_pivot_root,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
    libc::SYS_acct,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_syslog,
    libc::SYS_quotactl,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
];

/// `clone` flags that create namespaces: refused with `EPERM`.
const NAMESPACE_FLAGS: &[libc::c_int] = &[
    libc::CLONE_NEWNS,
    libc::CLONE_NEWUSER,
    libc::CLONE_NEWNET,
    libc::CLONE_NEWPID,
    libc::CLONE_NEWUTS,
    libc::CLONE_NEWIPC,
    libc::CLONE_NEWCGROUP,
];

fn arch() -> Result<TargetArch, String> {
    std::env::consts::ARCH
        .try_into()
        .map_err(|e| format!("seccomp on {}: {e:?}", std::env::consts::ARCH))
}

fn compile(rules: BTreeMap<i64, Vec<SeccompRule>>, errno: u32) -> Result<BpfProgram, String> {
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(errno), arch()?)
        .map_err(|e| e.to_string())?;
    filter.try_into().map_err(|e: seccompiler::BackendError| e.to_string())
}

/// The filters, in the order they are installed: the deny list (`EPERM`), then `clone3`
/// (`ENOSYS`, so libc falls back to `clone`, whose flags a filter can inspect).
pub fn filters() -> Result<Vec<BpfProgram>, String> {
    let mut denied: BTreeMap<i64, Vec<SeccompRule>> = DENIED.iter().map(|&n| (n, Vec::new())).collect();
    let clone_rules = NAMESPACE_FLAGS
        .iter()
        .map(|&flag| {
            let flag = flag as u64;
            SeccompCondition::new(0, SeccompCmpArgLen::Qword, SeccompCmpOp::MaskedEq(flag), flag)
                .and_then(|c| SeccompRule::new(vec![c]))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    denied.insert(libc::SYS_clone, clone_rules);
    let clone3: BTreeMap<i64, Vec<SeccompRule>> = [(libc::SYS_clone3, Vec::new())].into();
    Ok(vec![
        compile(denied, libc::EPERM as u32)?,
        compile(clone3, libc::ENOSYS as u32)?,
    ])
}

/// Installs the filters on this thread (and everything it execs). Needs `no_new_privs`.
pub fn apply() -> Result<(), String> {
    for f in filters()? {
        seccompiler::apply_filter(&f).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_filters_compile_for_this_architecture() {
        let f = super::filters().unwrap();
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|p| !p.is_empty()));
    }
}
