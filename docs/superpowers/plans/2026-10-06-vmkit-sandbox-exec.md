# vmkit generalised sandbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `vmkit::sandbox` a public, general-purpose rootless sandbox that runs any program, not only a VMM. It must support:
- a subuid-mapped user namespace;
- an overlay or read-only host root;
- an optional nested user namespace;
- a tap-less egress-policed network;
- a seccomp filter.

potter's `NsExecutor` (potter spec §9.4) can then run build steps on it, while VMMs keep running exactly as they do today.

**Architecture:**
- The library turns a public `Spec` into the helper's JSON `Plan` and starts `vmkit-sandbox run <plan>`.
- The helper grows two stages:
  - `userns` maps a subordinate id range with `newuidmap`/`newgidmap`;
  - `init` gains root kinds (empty tmpfs, read-only host, overlay) and supervises the program as PID 1. With `nest`, it maps a nested user namespace for the program from outside.
- The VMM path (`VmSpec`) becomes a client of the same `Spec`: empty root, the caller's own ids, and the VMM bound at `/vmm`. Its behaviour and tests are unchanged.

**Tech Stack:** Rust 2024 (MSRV 1.85), rustix 1.1, libc, serde, `seccompiler` 0.5 (new, Linux only); `newuidmap`/`newgidmap` (uidmap), `pasta`, `nft`, `ip`.

**Spec:** potter design spec, `AlfonsoCampodonico/potter` `docs/superpowers/specs/2026-10-04-potter-design.md`:
- §4 "Changes in `vmkit`": a generalised `sandbox` and `net` without a tap;
- §9.4 `NsExecutor`: sandbox layout U1/U2, hardening;
- §9.5: network policy.

The VMM sandbox's original requirements are kiln spec §9.2/§9.3, and they stay binding.

## Global Constraints

- **Platform:** Linux ≥ 5.12 for sandbox features (overlay in userns needs 5.11; `mount_setattr` needs 5.12). The crate must still build and its unit tests pass on macOS. The helper prints "only Linux is supported" there.
- **Unsafe code:** `src/` keeps `#![forbid(unsafe_code)]` in the library. The helper keeps `#![deny(unsafe_code)]`, and every `unsafe` block carries a `// SAFETY:` comment.
- **No regression on the VMM path:** every existing test in `tests/sandbox.rs`, `tests/contract.rs`, `tests/network.rs` and `tests/pause.rs` keeps passing. kiln relies on `sandbox::pid_file`, `sandbox::cgroups_available` / `vmkit::cgroups_available`, `NetSpec` and `net::{GATEWAY, GUEST, PREFIX, PortForward, Protocol}`, and these stay source-compatible.
- **Refusals:** the helper still refuses to run as root. A `Spec` that asks for something unsafe or impossible is refused by `spawn` with `Error::InvalidSpec`, before any process starts.
- **Prerequisites:** a missing prerequisite (no `newuidmap`, no subuid range, a range smaller than `count`) is `Error::Unsupported`-class with a message naming it.
- **Setup failures:** setup failures inside the helper exit 125 with one line `vmkit-sandbox: <what>: <why>` on stderr. A program's own exit code or signal is mirrored.
- **Formatting:** rustfmt `max_width = 120` (existing `rustfmt.toml`); clippy `-D warnings` on all targets.
- **Commits:** no Claude attribution trailers or footers (user preference).

## Review Focus

1. **Escape from the nested namespace:** a program under `nest` must have no capability over the sandbox's net namespace or mount namespace. That means `nft flush ruleset`, `ip link add` and `mount -t tmpfs` all fail, and creating another user namespace fails. It also must not be able to `ptrace` or signal `init` into giving it U1 capabilities.
2. **Subordinate mapping correctness:** inside, uid 0 is the caller and uids 1..=count are the subuid range. A file the program creates as uid 1000 is owned on the host by `subuid_start + 999`. Nothing outside the range is mapped.
3. **Overlay whiteouts and opaque directories:**
   - deleting a lower file leaves a 0/0 char device in `upper`;
   - replacing a directory leaves `user.overlay.opaque`;
   - the overlay never writes `trusted.*` xattrs.
4. **Read-only host root:** with `Root::Host`, every host mount is read-only, recursively. Only `Mount::Bind { writable: true }` targets can be written, and `/proc` is the sandbox's own PID namespace.
5. **Teardown:** killing the `Sandbox` (or the caller dying) kills every process in it, including daemons the program forked and `pasta`, within the pid namespace's teardown. Nothing is left behind that holds the overlay mounted.

---

## File structure

| File | Change |
|---|---|
| `src/sandbox.rs` | Public `Spec`, `Command`, `Program`, `Root`, `Mount`, `Ids`, `User`, `Network`, `Limits`, `Cgroup`, `Stdio`, `Sandbox`, `spawn()`. The helper `Plan` (doc-hidden) plus resolution of host binaries, subid ranges and the net plan. The VMM `spawn` is rebuilt on these. |
| `src/subid.rs` (new) | Parsing `/etc/subuid` and `/etc/subgid` (by name or uid), and choosing a range of `count` ids. |
| `src/net.rs` | `pub const NAMESERVER`, `egress_ruleset()` for a bare namespace, `Network` checks. |
| `src/bin/vmkit-sandbox.rs` | Stages `run`, `userns`, `init`; root kinds; supervision and nesting; seccomp. |
| `src/seccomp.rs` (new, Linux, used by the helper through `#[doc(hidden)] pub mod`) | The deny-list filter. |
| `src/lib.rs` | Re-exports; `sandbox` is no longer `doc(hidden)`. |
| `tests/sandbox.rs` | The existing VMM-sandbox tests are ported to the public API. |
| `tests/exec.rs` (new) | Generic sandbox suite (ids, roots, nest, network, seccomp, teardown). |
| `Cargo.toml` | `seccompiler = "0.5"` (Linux). |
| `.github/workflows/ci.yml` | Install `uidmap`; give the runner a subuid range; run `tests/exec.rs`. |
| `README.md` | "Sandboxing any program" section. |

## The public API (normative)

```rust
/// What the sandbox runs.
pub enum Program {
    /// A host file bound read-only into the root at `target` (absolute; for `Root::Empty`).
    Bound { host: PathBuf, target: PathBuf },
    /// An absolute path inside the root (for `Root::Host` it is a host path).
    Path(PathBuf),
}

pub struct User { pub uid: u32, pub gid: u32, pub groups: Vec<u32> }

pub struct Command {
    pub program: Program,
    /// argv[0]; defaults to the program's file name.
    pub arg0: Option<String>,
    pub args: Vec<String>,
    /// The program's whole environment; nothing is inherited.
    pub env: Vec<(String, String)>,
    /// Inside the sandbox; must be absolute. Default `/`.
    pub cwd: PathBuf,
    /// Ids inside the program's user namespace. `None`: the caller's own ids under `Ids::Caller`, root otherwise.
    pub user: Option<User>,
}

pub enum Root {
    /// A read-only 1 MiB tmpfs holding only the program and the mounts (the VMM sandbox).
    Empty,
    /// The host's tree, recursively read-only, nosuid and nodev, with a fresh `/proc`. Mount targets must already exist.
    Host,
    /// An overlay of `lowers` (top first) with `upper` and `work` (same filesystem), mounted with `userxattr`,
    /// with `/proc`, `/sys` (read-only), and a `/dev` holding null, zero, full, random, urandom, tty,
    /// pts (devpts) and shm (tmpfs). Mount points missing from the root are created in the upper.
    Overlay { lowers: Vec<PathBuf>, upper: PathBuf, work: PathBuf },
}

pub enum Mount {
    /// `source` opened without following a final symlink.
    Bind { source: PathBuf, target: PathBuf, writable: bool },
    Tmpfs { target: PathBuf, size_mib: u32 },
}

pub enum Ids {
    /// The caller's uid and gid only, identity-mapped; the program is never root (the VMM sandbox).
    Caller,
    /// Root inside is the caller; ids 1..=count map onto the caller's `/etc/subuid` and `/etc/subgid` ranges.
    Subordinate { count: u32 },
}

pub enum Network {
    /// A network namespace with only loopback (down under `Root::Empty`, up otherwise).
    None,
    /// The VM network: a tap, forwards, and the nftables policy (kiln spec §9.3).
    Tap(NetSpec),
    /// No tap: `pasta` egress for the namespace's own processes, policed by the same deny and allow sets.
    /// Forwards are refused. DNS is answered at [`net::NAMESERVER`].
    Egress(NetSpec),
}

pub struct Cgroup { pub memory_mib: u32, pub cpu_percent: u32, pub tasks: u32 }

pub struct Limits {
    pub open_files: u64,
    pub processes: u64,
    /// A systemd user scope with these limits, when `cgroups_available()`; ignored otherwise.
    pub cgroup: Option<Cgroup>,
}

pub struct Spec {
    pub command: Command,
    pub root: Root,
    pub mounts: Vec<Mount>,
    pub ids: Ids,
    pub network: Network,
    /// Run the program in a nested user namespace with no capability over the sandbox's
    /// namespaces (requires `Ids::Subordinate` and a root other than `Empty`).
    pub nest: bool,
    /// Apply the deny-list seccomp filter to the program.
    pub seccomp: bool,
    pub limits: Limits,
    /// Created if missing; holds the plan, the root mount point and the pid file.
    pub run_dir: PathBuf,
}

pub struct Stdio { pub stdin: std::process::Stdio, pub stdout: std::process::Stdio, pub stderr: std::process::Stdio }

/// A running sandbox: the helper process, in a process group of its own.
pub struct Sandbox { /* std::process::Child */ }
impl Sandbox {
    pub fn id(&self) -> u32;
    pub fn stdin(&mut self) -> Option<ChildStdin>;   // take
    pub fn stdout(&mut self) -> Option<ChildStdout>; // take
    pub fn stderr(&mut self) -> Option<ChildStderr>; // take
    pub fn wait(&mut self) -> std::io::Result<ExitStatus>;
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>>;
    /// SIGKILL to the helper; every process in the sandbox dies with it.
    pub fn kill(&mut self) -> std::io::Result<()>;
}

pub fn spawn(spec: &Spec, stdio: Stdio) -> Result<Sandbox>;
pub fn pid_file(run_dir: &Path) -> PathBuf;   // unchanged
pub fn cgroups_available() -> bool;           // unchanged
```

`Spec::check()` (called by `spawn`) refuses each of the following with `Error::InvalidSpec`:
- a relative or `..`-containing `cwd`, mount target or `Program` target;
- `Program::Bound` with a root other than `Empty`, or `Program::Path` with `Empty`;
- `nest` without `Ids::Subordinate`, or with `Root::Empty`;
- `Overlay` with no lowers;
- `Egress` with forwards;
- `Subordinate { count: 0 }`, or a count above 4 294 967 294;
- `user` under `Ids::Caller`, or `user` ids above `count`.

## Helper stages (normative)

```
run <plan>      host user namespace
  ├─ Ids::Caller:      unshare(USER|PID), identity map, then `continue` below
  └─ Ids::Subordinate: spawn `userns <plan>` (socket on stdin), wait "unshared\n",
                        newuidmap <pid> 0 <uid> 1 1 <subuid> <count>; newgidmap likewise,
                        send "mapped\n", mirror its exit
userns <plan>   pdeathsig KILL; unshare(USER); "unshared\n"; wait "mapped\n"; unshare(PID); `continue`
continue:       max_user_namespaces = nest ? 1 : 0; RLIMIT_CORE 0; PR_SET_DUMPABLE 0; ambient SETUP caps;
                spawn `init <plan>` (first child = PID 1), pid file, ready/go + pasta (Tap or Egress), mirror
init <plan>     pdeathsig; checks; unshare(NS|NET|IPC|UTS); net setup; ready/go; mounts → root; pivot_root;
                rlimits; keyring; PR_SET_DUMPABLE 0;
  ├─ Root::Empty && !nest: exec the program as PID 1 (today's VMM path, byte for byte)
  └─ otherwise: fork (single-threaded): child [nest: unshare(USER), "unshared", wait "mapped"] → exec;
                parent [nest: write /proc/<child>/{uid_map,gid_map} "0 0 <count+1>", send "mapped"]
                then reap every child until the program exits; exit mirroring the program's status
exec:           [nest: write max_user_namespaces 0]; setgroups/setresgid/setresuid(user); chdir(cwd);
                no_new_privs; clear ambient + inheritable caps; [seccomp]; execve(program, args, env)
```

Rulings fixed in this plan, each recorded in the ledger by Task 5:
- **U2 shares U1's mount and PID namespaces; it has no namespaces of its own** (spec §9.4 lists its own mount and PID namespaces).
  - Stricter: U2 owns no mount namespace, so it can't mount at all.
  - `init` is PID 1 of U1's namespace, so U2 can't signal it (PID-1 protection), and `PR_SET_DUMPABLE 0` plus yama stop `ptrace`.
  - A PID namespace of the program's own would make the program PID 1 (no default signal handling, no zombie reaping) and need a second supervisor.
  - Cost if wrong: one more fork plus `NEWPID|NEWNS`.

---

### Task 1: Public `Spec`, the helper plan, and the VMM path on top of it

**Files:**
- Modify: `src/sandbox.rs`, `src/lib.rs`, `src/bin/vmkit-sandbox.rs`, `tests/sandbox.rs`
- Test: unit tests in `src/sandbox.rs`; `tests/sandbox.rs` (ported, unchanged assertions)

**Interfaces:**
- Produces: every type in "The public API". `spawn(&Spec, Stdio) -> Result<Sandbox>`.
- Also produces the doc-hidden `Plan { spec: Spec, root_dir: PathBuf, pid_file: PathBuf, subid: Option<SubidPlan>, net: Option<NetPlan> }`:
  - `SubidPlan { newuidmap, newgidmap, uid_start, gid_start, count }`;
  - `NetPlan { ip, kind: NetKind }`, where `NetKind::{Loopback, Tap { nft, ruleset, pasta, pasta_args }, Egress { nft, ruleset, pasta, pasta_args }}`.
- The crate-private `vmm_spec(spec: &VmSpec, vmm: &Path, args: &[String]) -> Spec` builds the VMM sandbox:
  - `Program::Bound { host: vmm, target: "/vmm" }`, `Root::Empty`, `Ids::Caller`;
  - `Network::Tap(net)` or `Network::None`;
  - limits `open_files 1024`, `processes 256`, and a cgroup from `scope_properties`' numbers.

In this task `Ids::Subordinate`, `Root::Host`, `Root::Overlay`, `nest`, `Network::Egress` and `seccomp` pass `check()`. The helper fails on them with `vmkit-sandbox: <feature>: not implemented yet` and exit 125. Tasks 2–7 replace each one.

- [ ] **Step 1: Unit tests for `check()` and plan round-trip** in `src/sandbox.rs` `mod tests`. Keep the four existing tests: `the_vmm_sees_only_its_devices_kernel_disks_and_directory` becomes a test of `vmm_spec(..).mounts`, with the same expected list minus `/vmm`.

```rust
fn exec_spec() -> Spec {
    Spec {
        command: Command {
            program: Program::Path("/bin/sh".into()),
            arg0: None,
            args: vec!["-c".into(), "true".into()],
            env: vec![("PATH".into(), "/bin".into())],
            cwd: "/".into(),
            user: None,
        },
        root: Root::Overlay { lowers: vec!["/l".into()], upper: "/u".into(), work: "/w".into() },
        mounts: Vec::new(),
        ids: Ids::Subordinate { count: 65536 },
        network: Network::None,
        nest: true,
        seccomp: true,
        limits: Limits { open_files: 1024, processes: 1024, cgroup: None },
        run_dir: "/run/s".into(),
    }
}

#[test]
fn a_well_formed_spec_passes() {
    assert_eq!(exec_spec().check(), Ok(()));
}

#[test]
fn malformed_specs_are_refused() {
    let cases: Vec<(&str, Box<dyn Fn(&mut Spec)>)> = vec![
        ("relative cwd", Box::new(|s| s.command.cwd = "app".into())),
        ("dotdot mount", Box::new(|s| s.mounts.push(Mount::Tmpfs { target: "/a/../b".into(), size_mib: 1 }))),
        ("bound program outside an empty root", Box::new(|s| s.command.program = Program::Bound { host: "/x".into(), target: "/x".into() })),
        ("nest without subordinate ids", Box::new(|s| { s.ids = Ids::Caller; })),
        ("nest in an empty root", Box::new(|s| { s.root = Root::Empty; s.command.program = Program::Bound { host: "/x".into(), target: "/x".into() }; })),
        ("overlay without lowers", Box::new(|s| s.root = Root::Overlay { lowers: vec![], upper: "/u".into(), work: "/w".into() })),
        ("egress with forwards", Box::new(|s| s.network = Network::Egress(NetSpec { forwards: vec![net::PortForward { protocol: net::Protocol::Tcp, host: 8080, guest: 80 }], ..Default::default() }))),
        ("zero subordinate ids", Box::new(|s| s.ids = Ids::Subordinate { count: 0 })),
        ("user beyond the range", Box::new(|s| s.command.user = Some(User { uid: 70000, gid: 0, groups: vec![] }))),
        ("relative program path", Box::new(|s| s.command.program = Program::Path("sh".into()))),
    ];
    for (what, mutate) in cases {
        let mut s = exec_spec();
        mutate(&mut s);
        assert!(matches!(s.check(), Err(_)), "{what} was accepted");
    }
}

#[test]
fn the_vmm_sandbox_is_an_empty_root_with_the_callers_ids() {
    let s = vmm_spec(&spec(), Path::new("/bin/vmm"), &["--x".into()]);
    assert_eq!(s.root, Root::Empty);
    assert_eq!(s.ids, Ids::Caller);
    assert!(!s.nest && !s.seccomp);
    assert_eq!(s.command.program, Program::Bound { host: "/bin/vmm".into(), target: "/vmm".into() });
    assert_eq!(s.check(), Ok(()));
}
```

`check()` returns `std::result::Result<(), String>`. `spawn` maps it to `Error::InvalidSpec`. Derive `Debug, Clone, PartialEq, Eq, Serialize, Deserialize` on every API type except `Stdio` and `Sandbox`. `NetSpec`, `Cidr`, `PortForward`, `Protocol` and `Egress` gain `Serialize, Deserialize`. `Cidr` (de)serialises as its `Display`/`FromStr` string.

- [ ] **Step 2: Run them; expect compile failure** (types missing). Command: `cargo test --lib sandbox`. Expected: FAIL, unresolved `Spec`.

- [ ] **Step 3: Implement the types, `check()`, `vmm_spec`, `Plan`, the generic `spawn`, and the `Sandbox` handle.**
  - The VMM's `spawn` builds `vmm_spec` and the plan with `pid_file` and `net`. It runs through the same code path, keeps `process::spawn` (console log, stderr log, process group) and `.with_vmm_pid_file`, and keeps its systemd scope.
  - The generic `spawn` creates `run_dir`, `run_dir/root` and `run_dir/sock`, writes `run_dir/sandbox.json`, then starts `systemd-run --user --scope ... -- helper run plan` when `limits.cgroup` is set and cgroups are available, or `helper run plan` otherwise.
    - It uses `process_group(0)` and the caller's `Stdio`.
    - Scope properties are `MemoryMax=<memory_mib>M`, `CPUQuota=<cpu_percent>%`, `TasksMax=<tasks>`.
  - The helper reads `plan.spec`:
    - `Root::Empty` with `Program::Bound` does exactly what `init` did before. Mounts are `Bind` (with `attach`) or `Tmpfs` (mounted inside the root, mode 0755, `size=<n>m`), then the read-only remount.
    - It binds `Program::Bound.host` at `target`, sets argv[0] from `arg0` or the file name, and execs `target`.
    - Under `Root::Empty`, `env` is empty for the VMM (as before). `Command::env` is passed with `env_clear()`.
  - Port `tests/sandbox.rs`: `Sandbox::plan()` becomes `Sandbox::spec()`, which returns a `vmkit::sandbox::Spec`.
    - Busybox is `Program::Bound { host: BUSYBOX, target: "/vmm" }`.
    - Its binds become `Mount::Bind` with the same targets.
    - `network`: `Network::Tap(..)` where the old test passed a `NetPlan`. The two tests that hand-wrote a ruleset (`the_network_namespace_gets_the_tap_and_pasta`, `the_vmm_opens_no_connection_through_pasta`) now pass a `NetSpec`, and the library builds the ruleset.
    - `command()`/`output()`/`spawn()` call `vmkit::sandbox::spawn` with piped stdio.
    - Every assertion stays as it is.

- [ ] **Step 4: Run unit tests on macOS, then the sandbox suite in Lima.**
  - macOS: `cargo test --lib`. Expected: PASS.
  - Lima: `limactl shell vmkit -- bash -lc 'cd <worktree> && CARGO_TARGET_DIR=$HOME/t/vmkit-sx cargo build --bin vmkit-sandbox && VMKIT_SANDBOX=$HOME/t/vmkit-sx/debug/vmkit-sandbox CARGO_TARGET_DIR=$HOME/t/vmkit-sx cargo test --test sandbox'`. Before the first run, install the AppArmor profile for that helper path with `scripts/install-apparmor.sh`.
  - Expected: all 10 existing sandbox tests PASS (the network ones need `VMKIT_TEST_NET=1` and the fixture; `the_network_namespace_gets_the_tap_and_pasta` runs without it).
  - Then run `cargo test --test contract` with the kernel env, unchanged. Expected: PASS.

- [ ] **Step 5: Commit** `sandbox: a public Spec for any program; the VMM sandbox is one`.

### Task 2: Subordinate ids

**Files:**
- Create: `src/subid.rs`
- Modify: `src/sandbox.rs`, `src/bin/vmkit-sandbox.rs`
- Test: `src/subid.rs` unit tests; `tests/exec.rs` (new)

**Interfaces:**
- Produces: `subid::Range { start: u32, count: u32 }` and `subid::find(file_text: &str, user: &str, uid: u32, count: u32) -> Result<Range, String>`. It takes the first line whose name is `user` or the numeric `uid` and whose count ≥ `count`, and returns `start` with `count`.
- Produces: `sandbox::resolve_subids(count) -> Result<SubidPlan>`. It reads `/etc/subuid` and `/etc/subgid`, finds `newuidmap`/`newgidmap` with `binary::find_system`, and gets the user name from `$USER`, else from `getpwuid` through `/etc/passwd`.
- A missing range or binary returns `Error::Unsupported`-style text naming `/etc/subuid` or `newuidmap`. `Error` gains `Prerequisite(String)`, displayed as `"missing prerequisite: {0}"`.

- [ ] **Step 1: Unit tests** for `subid::find`:

```rust
#[test]
fn ranges_match_by_name_or_uid_and_must_be_large_enough() {
    let text = "bob:100000:65536\n# comment\nalice:200000:1000\n1000:300000:65536\n";
    assert_eq!(find(text, "bob", 501, 65536), Ok(Range { start: 100000, count: 65536 }));
    assert_eq!(find(text, "carol", 1000, 65536), Ok(Range { start: 300000, count: 65536 }));
    assert!(find(text, "alice", 502, 65536).unwrap_err().contains("at least 65536"));
    assert!(find(text, "dave", 503, 1).unwrap_err().contains("no range for dave"));
    assert!(find("bob:x:1\n", "bob", 501, 1).is_err());
}
```

- [ ] **Step 2: Run; expect FAIL** (`cargo test --lib subid`).

- [ ] **Step 3: Implement `subid.rs`**, then the helper stages `userns` and the shared `continue_in_userns`, following "Helper stages". The `run` side:

```rust
fn map_subordinate(plan: &Plan, child: u32) {
    let s = plan.subid.as_ref().unwrap_or_else(|| fail("subordinate ids", "the plan has no ranges"));
    let (uid, gid) = (rustix::process::getuid().as_raw(), rustix::process::getgid().as_raw());
    for (tool, own, start) in [(&s.newuidmap, uid, s.uid_start), (&s.newgidmap, gid, s.gid_start)] {
        let status = Command::new(tool)
            .args([child.to_string(), "0".into(), own.to_string(), "1".into(), "1".into(), start.to_string(), s.count.to_string()])
            .stdin(Stdio::null())
            .status()
            .unwrap_or_else(|e| fail(&format!("starting {}", tool.display()), e));
        if !status.success() {
            fail(&tool.display().to_string(), format!("exited with {status}"));
        }
    }
}
```

`userns` sets pdeathsig KILL, then:

```rust
unshare(UnshareFlags::NEWUSER);
// talks over stdin: "unshared\n" → wait for "mapped\n"
unshare(UnshareFlags::NEWPID);
continue_in_userns(&plan, plan_path);
```

`continue_in_userns` is today's `run` tail: `max_user_namespaces`, core limit, `prctl(PR_SET_DUMPABLE, 0)` (rustix `set_dumpable_behavior`), `pass_setup_capabilities`, then spawn `init`, write the pid file, do the ready/go handshake, attach pasta, and mirror.
- Under `Ids::Caller` it runs in-process after the identity map, as today.
- `max_user_namespaces` is written as `1` when `plan.spec.nest`, else `0`.
- The program's default user under `Subordinate` is 0/0 with no groups.

- [ ] **Step 4: Integration tests** in the new `tests/exec.rs` (Linux only, skipped without `VMKIT_SANDBOX`, as in `tests/sandbox.rs`). For now they use `Root::Host` = **not yet**, so they use `Root::Empty` with busybox bound at `/bin/busybox` and `Ids::Subordinate`:

```rust
#[test]
fn subordinate_ids_make_the_caller_root_and_map_the_range() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_empty(&["sh", "-c", "id -u; id -g; cat /proc/self/uid_map"], Ids::Subordinate { count: 65536 });
    let lines: Vec<&str> = out.stdout.lines().map(str::trim).collect();
    assert_eq!(&lines[..2], ["0", "0"]);
    let caller = rustix::process::getuid().as_raw();
    assert_eq!(lines[2].split_whitespace().collect::<Vec<_>>(), ["0", &caller.to_string(), "1"]);
    let second: Vec<&str> = lines[3].split_whitespace().collect();
    assert_eq!((second[0], second[2]), ("1", "65536"));
}

#[test]
fn a_file_made_by_uid_1000_belongs_to_the_subordinate_range_on_the_host() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_empty_with_bind(&["sh", "-c", "touch /w/f && chown 1000:1000 /w/f"], Ids::Subordinate { count: 65536 });
    assert!(out.status.success(), "{}", out.stderr);
    let meta = std::fs::metadata(t.dir.path().join("w/f")).unwrap();
    let start = t.subuid_start();
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&meta), start + 999);
}

#[test]
fn a_missing_range_is_named() {
    let Some(_t) = Fixture::new() else { return };
    let err = vmkit::sandbox::spawn(&spec_needing(u32::MAX - 1), stdio()).unwrap_err().to_string();
    assert!(err.contains("/etc/subuid"), "{err}");
}
```

`Fixture` holds the tempdir, busybox at `/usr/bin/busybox`, and helpers that build a `Spec` and collect `Output`s. Its `run_empty` uses `Root::Empty`, `Program::Bound { host: busybox, target: "/bin/busybox" }`, `arg0` = the applet, and `cwd` = `/`. The writable bind is the tempdir's `w` at `/w`. `chown` needs `CAP_CHOWN`: under `Subordinate`, the program runs as root in U1 without `nest`, keeps its capabilities over the exec only if it isn't cleared. So `exec` clears the *ambient* set (as today) but keeps the permitted/effective sets for uid 0, since root's exec keeps full capabilities. Under `Ids::Caller` the program is non-root, so it has none.

- [ ] **Step 5: Run in Lima.** `cargo test --test exec` → the 3 tests PASS; `cargo test --test sandbox` → PASS.

- [ ] **Step 6: Commit** `sandbox: subordinate id ranges through newuidmap`.

### Task 3: `Root::Host` and supervision

**Files:**
- Modify: `src/bin/vmkit-sandbox.rs`
- Test: `tests/exec.rs`

**Interfaces:**
- The helper gains:
  - `host_root(plan)`, which recursively binds `/` read-only onto `root_dir` and puts a fresh `/proc` on it;
  - `supervise(plan) -> !`, which forks, execs the program in the child, reaps in the parent and mirrors;
  - `exec_program(plan) -> !`.

- [ ] **Step 1: Integration tests**

```rust
#[test]
fn the_host_root_is_read_only_except_writable_binds() {
    let Some(t) = Fixture::new() else { return };
    let w = t.dir.path().join("w");
    let script = format!("cat /etc/hostname >/dev/null && ! touch /etc/vmkit-probe 2>/dev/null && ! touch /tmp/vmkit-probe 2>/dev/null && touch {}/ok", w.display());
    let out = t.run_host(&["/bin/sh", "-c", &script], vec![Mount::Bind { source: w.clone(), target: w.clone(), writable: true }]);
    assert!(out.status.success(), "{}", out.stderr);
    assert!(w.join("ok").exists());
}

#[test]
fn proc_is_the_sandboxs_own_and_the_program_is_not_pid_1() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_host(&["/bin/sh", "-c", "echo $$; ls /proc | grep -c '^[0-9]'"], vec![]);
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines[0], "2");
    assert!(lines[1].trim().parse::<u32>().unwrap() <= 4, "{}", out.stdout);
}

#[test]
fn env_cwd_and_user_are_exactly_the_commands() {
    let Some(t) = Fixture::new() else { return };
    let mut s = t.host_spec(&["/bin/sh", "-c", "pwd; id -u; id -g; env | sort"]);
    s.command.env = vec![("A".into(), "1".into()), ("PATH".into(), "/usr/bin:/bin".into())];
    s.command.cwd = "/usr".into();
    s.command.user = Some(User { uid: 1000, gid: 1001, groups: vec![] });
    let out = t.output(&s);
    assert_eq!(out.stdout, "/usr\n1000\n1001\nA=1\nPATH=/usr/bin:/bin\nPWD=/usr\nSHLVL=1\n_=/usr/bin/env\n".replace("SHLVL=1\n_=/usr/bin/env\n", &tail(&out.stdout)));
}

#[test]
fn exit_codes_and_signals_of_the_program_are_mirrored() {
    let Some(t) = Fixture::new() else { return };
    assert_eq!(t.run_host(&["/bin/sh", "-c", "exit 7"], vec![]).status.code(), Some(7));
    let killed = t.run_host(&["/bin/sh", "-c", "kill -TERM $$"], vec![]);
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&killed.status), Some(15));
}

#[test]
fn background_processes_die_with_the_program() {
    let Some(t) = Fixture::new() else { return };
    let w = t.dir.path().join("w");
    let script = format!("(sleep 2; touch {}/late) & exit 0", w.display());
    let out = t.run_host(&["/bin/sh", "-c", &script], vec![Mount::Bind { source: w.clone(), target: w.clone(), writable: true }]);
    assert!(out.status.success());
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(!w.join("late").exists(), "a background process outlived the sandbox");
}
```

The `env` test compares the exact set it controls: write it as `assert!` that the output's lines are `/usr`, `1000` and `1001`, and that `env` has `A=1` and `PATH=...` and no `HOME`/`USER`/`VMKIT_*` from the caller. No `tail` helper is needed; drop it when transcribing.

- [ ] **Step 2: Run; expect FAIL** (`not implemented yet: Root::Host`).

- [ ] **Step 3: Implement.**
  - `Root::Host`:
    - `open_tree(CWD, "/", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE)`;
    - then `mount_setattr(fd, "", AT_EMPTY_PATH | AT_RECURSIVE, {attr_set: RDONLY|NOSUID|NODEV})` through `libc::syscall(libc::SYS_mount_setattr, ...)`, with a local `#[repr(C)] struct MountAttr { attr_set: u64, attr_clr: u64, propagation: u64, userns_fd: u64 }`, `MOUNT_ATTR_RDONLY = 0x1`, `NOSUID = 0x2`, `NODEV = 0x4`, and `AT_RECURSIVE = 0x8000`;
    - `move_mount` onto `root_dir`;
    - mount `proc` at `root_dir/proc` (`nosuid,nodev,noexec`);
    - mounts: a `Bind` needs an existing target and attaches like today's `attach`. An absent target fails `"<target> must exist under Root::Host"`. `Tmpfs` is mounted over an existing directory.
    - `pivot_root`.
  - `supervise`:
    - in the child (after `fork`): `exec_program`;
    - in the parent: loop `waitpid(None, WaitOptions::empty())`, remembering the status when the pid is the program's;
    - on `ECHILD` after the program has ended, `mirror(status)`.
  - `exec_program`:
    - `setgroups`/`setresgid`/`setresuid` through `rustix::thread` (`set_thread_groups`, `set_thread_res_gid`, `set_thread_res_uid`; single-threaded, so per-thread is per-process);
    - `chdir(cwd)`, `no_new_privs`, clear the ambient and inheritable sets;
    - `Command::new(path).arg0(..).args(..).env_clear().envs(..).exec()`.
  - `fork`:

```rust
/// Forks this single-threaded process.
fn fork() -> Option<u32> {
    #[allow(unsafe_code)]
    // SAFETY: `init` is single-threaded (it never spawns threads), so the child inherits no
    // lock held by another thread; it only makes syscalls and allocates before it execs or exits.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => fail("fork", std::io::Error::last_os_error()),
        0 => None,
        p => Some(p as u32),
    }
}
```

- [ ] **Step 4: Run in Lima.** `cargo test --test exec` → PASS (8 tests); `cargo test --test sandbox` → PASS.

- [ ] **Step 5: Commit** `sandbox: a read-only host root and a supervising init`.

### Task 4: `Root::Overlay`

**Files:**
- Modify: `src/bin/vmkit-sandbox.rs`
- Test: `tests/exec.rs`

**Interfaces:**
- The helper gains:
  - `overlay_root(plan)`: `fsopen("overlay")`, then `fsconfig_set_string` for `lowerdir+` per lower (bottom first, since `lowerdir+` appends; the API's `lowers` are top first, so iterate reversed), `upperdir`, `workdir` and `userxattr`, then `fsconfig_create`, `fsmount`, `move_mount` onto `root_dir`. When `lowerdir+` is refused with `EINVAL` (kernel < 6.8), it falls back to `mount(2)` with `lowerdir=<l1>:<l2>`. When that string is longer than 4000 bytes it fails with "too many layers for this kernel".
  - `container_mounts(root_dir, ids)`: `proc`; `sysfs` read-only; `/dev` (a `tmpfs` with `mode=0755,size=64k,nosuid,noexec`) holding binds of host `null zero full random urandom tty`, symlinks `fd -> /proc/self/fd`, `stdin/stdout/stderr -> /proc/self/fd/0..2`, `ptmx -> pts/ptmx`, then `pts` (`devpts`: `newinstance,ptmxmode=0666,mode=0620`, plus `gid=5` only under `Subordinate`) and `shm` (`tmpfs` `mode=1777,size=64m,nosuid,nodev`).

- [ ] **Step 1: Integration tests.** The lower is a busybox rootfs that the fixture builds in the tempdir: `bin/busybox` plus symlinks `sh ls cat rm mkdir touch chown id env sleep mknod` and `etc/old`. Upper and work are siblings in the tempdir (tmpfs `/tmp` in Lima; it supports `user.*` xattrs).

```rust
#[test]
fn an_overlay_root_records_changes_in_the_upper_with_user_xattrs() {
    let Some(t) = Fixture::new() else { return };
    let script = "rm /etc/old && mkdir -p /opt/new && echo hi >/opt/new/f && chown 1000:1000 /opt/new/f && rm -r /etc && mkdir /etc && echo x >/etc/fresh";
    let out = t.run_overlay(&["/bin/sh", "-c", script], Vec::new());
    assert!(out.status.success(), "{}", out.stderr);
    let upper = t.dir.path().join("upper");
    assert_eq!(std::fs::read_to_string(upper.join("opt/new/f")).unwrap(), "hi\n");
    // `etc` was replaced: an opaque directory, marked with a user xattr, never a trusted one.
    assert_eq!(xattr(&upper.join("etc"), "user.overlay.opaque").as_deref(), Some(&b"y"[..]));
    assert!(xattr(&upper.join("etc"), "trusted.overlay.opaque").is_none());
    let meta = std::fs::symlink_metadata(upper.join("opt/new/f")).unwrap();
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&meta), t.subuid_start() + 999);
}

#[test]
fn deleting_a_lower_file_leaves_a_whiteout() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_overlay(&["/bin/sh", "-c", "rm /bin/ls"], Vec::new());
    assert!(out.status.success(), "{}", out.stderr);
    let meta = std::fs::symlink_metadata(t.dir.path().join("upper/bin/ls")).unwrap();
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    assert!(meta.file_type().is_char_device() && meta.rdev() == 0);
}

#[test]
fn the_overlay_root_has_proc_dev_and_shm_and_mounts() {
    let Some(t) = Fixture::new() else { return };
    let cache = t.dir.path().join("cache");
    std::fs::create_dir(&cache).unwrap();
    let script = "test -c /dev/null && echo x >/dev/null && test -d /proc/self && test -d /dev/shm && touch /dev/shm/a && touch /cache/hit && ! touch /sys/x 2>/dev/null";
    let mounts = vec![Mount::Bind { source: cache.clone(), target: "/cache".into(), writable: true }, Mount::Tmpfs { target: "/run/secrets".into(), size_mib: 1 }];
    let out = t.run_overlay(&["/bin/sh", "-c", script], mounts);
    assert!(out.status.success(), "{}", out.stderr);
    assert!(cache.join("hit").exists());
    assert!(!t.dir.path().join("upper/cache/hit").exists(), "a bind mount's writes reached the upper");
}
```

`xattr(path, name) -> Option<Vec<u8>>` is a test helper over `rustix::fs::lgetxattr`; add `rustix` to `[dev-dependencies]` for Linux with feature `fs`.

- [ ] **Step 2: Run; expect FAIL** (`not implemented yet: Root::Overlay`).

- [ ] **Step 3: Implement** `overlay_root` and `container_mounts`, then mounts (`Bind`: create the target dir or file in the root when missing; `Tmpfs`: create the dir when missing), then `pivot_root`. The root stays writable.

- [ ] **Step 4: Run in Lima.** `cargo test --test exec` → PASS (11 tests).

- [ ] **Step 5: Commit** `sandbox: an overlay root with /proc, /sys and a minimal /dev`.

### Task 5: The nested user namespace

**Files:**
- Modify: `src/bin/vmkit-sandbox.rs`
- Test: `tests/exec.rs`

**Interfaces:**
- `supervise` does the nest handshake (see "Helper stages"). In the child, after "mapped", `exec_program` writes `0` to `/proc/sys/user/max_user_namespaces`.
- The parent writes `/proc/<pid>/uid_map` and `gid_map` with `0 0 <count + 1>` and no `setgroups` file (a privileged writer needs no `deny`).

- [ ] **Step 1: Integration tests** (overlay root, `nest: true`, `Network::None`):

```rust
#[test]
fn a_nested_program_cannot_touch_the_sandboxs_namespaces() {
    let Some(t) = Fixture::new() else { return };
    let script = "id -u; ! busybox ip link add d0 type dummy 2>/dev/null && ! mount -t tmpfs t /mnt 2>/dev/null && ! busybox unshare -U true 2>/dev/null && echo contained";
    let out = t.run_overlay_nested(&["/bin/sh", "-c", script]);
    assert_eq!(out.stdout, "0\ncontained\n", "{}", out.stderr);
}

#[test]
fn a_nested_program_still_owns_files_as_root_and_subordinate_users() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_overlay_nested(&["/bin/sh", "-c", "touch /a && chown 1000:1000 /a && cat /proc/self/uid_map"]);
    assert!(out.status.success(), "{}", out.stderr);
    assert_eq!(out.stdout.split_whitespace().collect::<Vec<_>>(), ["0", "0", "65537"]);
    let meta = std::fs::symlink_metadata(t.dir.path().join("upper/a")).unwrap();
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&meta), t.subuid_start() + 999);
}

#[test]
fn a_nested_program_cannot_signal_or_trace_init() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_overlay_nested(&["/bin/sh", "-c", "kill -KILL 1; sleep 0.2; echo alive"]);
    assert_eq!(out.stdout, "alive\n", "{}", out.stderr);
}
```

The fixture's busybox lower gains the `mount ip unshare kill` symlinks (busybox applets).

- [ ] **Step 2: Run; expect FAIL** (`not implemented yet: nest`).

- [ ] **Step 3: Implement the handshake** with a `UnixStream::pair()` made before `fork`:
  - **Child:** `unshare(NEWUSER)`, writes `unshared\n`, reads `mapped\n`, then `exec_program`.
  - **Parent:** reads `unshared\n`, writes the two maps (`fs::write(format!("/proc/{pid}/uid_map"), …)`; `/proc` is the sandbox's own for `Host` and `Overlay`), then writes `mapped\n`.
  - Ledger the U2 ruling from the plan header in this task.

- [ ] **Step 4: Run in Lima.** `cargo test --test exec` → PASS (14 tests).

- [ ] **Step 5: Commit** `sandbox: run the program in a nested user namespace`.

### Task 6: `Network::Egress` and loopback

**Files:**
- Modify: `src/net.rs`, `src/sandbox.rs`, `src/bin/vmkit-sandbox.rs`
- Test: `src/net.rs` unit tests; `tests/exec.rs`

**Interfaces:**
- Produces: `pub const NAMESERVER: Ipv4Addr` (= the old private `DNS_FORWARD`).
- Produces: `#[doc(hidden)] pub fn egress_ruleset(spec: &NetSpec, host: &[Ipv4Addr]) -> String`:

```
table inet vmkit {
  set deny { type ipv4_addr; flags interval; auto-merge;<deny> }
  set allow { type ipv4_addr; flags interval; auto-merge;<allow> }
  chain output {
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    meta nfproto ipv6 drop
    ct state established,related accept
    ip daddr <NAMESERVER> udp dport 53 accept
    ip daddr <NAMESERVER> tcp dport 53 accept
    oifname "egress0" ip daddr @allow accept
    oifname "egress0" ip daddr @deny drop
    oifname "egress0" accept
  }
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
  }
}
```

  The deny and allow sets are computed exactly as `ruleset` computes them (factor out `fn sets(spec, host) -> (String, String)`).
- Produces: `NetKind::Loopback`, which brings `lo` up with `ip link set lo up` and is used for `Network::None` under `Host`/`Overlay`. `Root::Empty` with `Network::None` keeps today's behaviour (no `ip`, `lo` down).

- [ ] **Step 1: Unit tests** in `src/net.rs`:

```rust
#[test]
fn the_egress_ruleset_polices_the_namespaces_own_traffic() {
    let r = egress_ruleset(&NetSpec::default(), &[Ipv4Addr::new(192, 168, 5, 15)]);
    assert!(r.contains("type filter hook output priority filter; policy drop;"));
    assert!(r.contains("192.168.5.15"));
    assert!(r.contains("169.254.0.0/16"));
    assert!(r.contains(&format!("ip daddr {NAMESERVER} udp dport 53 accept")));
    assert!(!r.contains(TAP), "a bare namespace has no tap");
    let open = egress_ruleset(&NetSpec { egress: Egress::Open, ..Default::default() }, &[]);
    assert!(!open.contains("169.254.0.0/16"));
}
```

- [ ] **Step 2: Run; expect FAIL** (`cargo test --lib net`).

- [ ] **Step 3: Implement** `egress_ruleset`, the `NetKind` variants in the plan, `setup_egress` in `init` (`lo` up, then `nft -f -`), and pasta attach for `Egress` (same `pasta_args` with no forwards).

- [ ] **Step 4: Integration tests** (`VMKIT_TEST_NET=1`, the fixture from `testguest/net-fixture.sh`; read that script for its allowed and denied fixture addresses and reuse the constants `tests/network.rs` uses):

```rust
#[test]
fn egress_reaches_public_addresses_but_not_private_or_metadata_ones() {
    let Some(t) = Fixture::net() else { return };
    let out = t.run_overlay_net(&["/bin/sh", "-c", &format!(
        "busybox nc -w 2 {PUBLIC} {PORT} </dev/null && echo public; busybox nc -w 2 169.254.169.254 80 </dev/null || echo metadata-blocked; busybox nc -w 2 {PRIVATE} {PORT} </dev/null || echo private-blocked"
    )]);
    assert_eq!(out.stdout, "public\nmetadata-blocked\nprivate-blocked\n", "{}", out.stderr);
}

#[test]
fn a_nested_program_cannot_flush_the_policy() {
    let Some(t) = Fixture::net() else { return };
    let out = t.run_overlay_net(&["/bin/sh", "-c", "busybox ip route del default 2>/dev/null || echo kept"]);
    assert_eq!(out.stdout, "kept\n", "{}", out.stderr);
}

#[test]
fn loopback_is_up_without_a_network() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_host(&["/bin/sh", "-c", "cat /sys/class/net/lo/operstate"], vec![]);
    assert_eq!(out.stdout.trim(), "unknown");
}
```

`PUBLIC`, `PRIVATE` and `PORT` follow `tests/network.rs`'s fixture constants. If the fixture serves on a different protocol, use its probe the same way the network suite does. The nested flush test uses `ip route del` because busybox has no `nft`: removing the default route needs `NET_ADMIN` over the netns, which is the same capability `nft` needs.

- [ ] **Step 5: Run in Lima** with the fixture. `cargo test --test exec` → PASS (17 tests); `cargo test --test sandbox` and `cargo test --test network` → PASS.

- [ ] **Step 6: Commit** `net: egress for a bare namespace, without a tap`.

### Task 7: Seccomp

**Files:**
- Create: `src/seccomp.rs`
- Modify: `Cargo.toml`, `src/lib.rs`, `src/bin/vmkit-sandbox.rs`
- Test: `tests/exec.rs`

**Interfaces:**
- Produces `#[doc(hidden)] pub mod seccomp` (Linux) with `pub fn filter() -> Result<seccompiler::BpfProgram, String>`, built for the compile-time arch (`x86_64` or `aarch64`) with default action `Allow`.
- The deny list (`EPERM`): `mount umount2 fsopen fsconfig fsmount fspick move_mount open_tree mount_setattr pivot_root unshare setns keyctl add_key request_key bpf perf_event_open userfaultfd kexec_load kexec_file_load init_module finit_module delete_module swapon swapoff reboot acct settimeofday clock_settime clock_adjtime adjtimex syslog quotactl quotactl_fd open_by_handle_at name_to_handle_at io_uring_setup io_uring_enter io_uring_register`.
- `clone3` returns `ENOSYS`, so libc falls back to `clone`.
- `clone` returns `EPERM` when `flags & F == F` for any `F` of `CLONE_NEWNS NEWUSER NEWNET NEWPID NEWUTS NEWIPC NEWCGROUP` (one `SeccompRule` per flag, `MaskedEq(F)`).
- `exec_program` applies it after `no_new_privs` and immediately before `exec` when `plan.spec.seccomp`.

- [ ] **Step 1: Integration tests**

```rust
#[test]
fn seccomp_denies_namespaces_mounts_and_keyrings_but_not_ordinary_work() {
    let Some(t) = Fixture::new() else { return };
    let mut s = t.overlay_spec(&["/bin/sh", "-c", "busybox unshare -n true 2>&1; mount -t tmpfs t /mnt 2>&1; echo ok >/tmp/f && cat /tmp/f && sleep 0.1 && ls / >/dev/null && echo done"]);
    s.seccomp = true;
    s.nest = false; // root in U1 would otherwise be allowed to unshare and mount
    let out = t.output(&s);
    assert!(out.stdout.contains("Operation not permitted"), "{}", out.stdout);
    assert!(out.stdout.ends_with("ok\ndone\n"), "{}", out.stdout);
}
```

- [ ] **Step 2: Run; expect FAIL** (seccomp not applied, so `unshare -n` succeeds as root in U1).

- [ ] **Step 3: Implement** with `seccompiler::{SeccompFilter, SeccompRule, SeccompCondition, SeccompCmpArgLen, SeccompCmpOp, SeccompAction, TargetArch}`, using syscall numbers from `libc::SYS_*`. `seccompiler::apply_filter(&prog)` is called in the helper; that is not `unsafe` for the caller. The `seccomp` module uses no `unsafe`, so the library's `forbid(unsafe_code)` holds.

- [ ] **Step 4: Run in Lima.** `cargo test --test exec` → PASS (18 tests). macOS `cargo test` still builds: `seccompiler` and the module are Linux-only.

- [ ] **Step 5: Commit** `sandbox: a seccomp deny list for programs`.

### Task 8: Cgroup limits for any program, teardown, docs and CI

**Files:**
- Modify: `src/sandbox.rs`, `README.md`, `.github/workflows/ci.yml`, `src/lib.rs`
- Test: `tests/exec.rs`

- [ ] **Step 1: Integration tests**

```rust
#[test]
fn killing_the_sandbox_ends_everything_in_it() {
    let Some(t) = Fixture::new() else { return };
    let w = t.dir.path().join("w");
    let mut s = t.host_spec(&["/bin/sh", "-c", &format!("(sleep 3; touch {}/late) & sleep 30", w.display())]);
    s.mounts.push(Mount::Bind { source: w.clone(), target: w.clone(), writable: true });
    let mut sb = vmkit::sandbox::spawn(&s, stdio()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    sb.kill().unwrap();
    sb.wait().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(4));
    assert!(!w.join("late").exists());
}

#[test]
fn a_cgroup_limits_memory_when_available() {
    let Some(t) = Fixture::new() else { return };
    if !vmkit::sandbox::cgroups_available() { return; }
    let mut s = t.host_spec(&["/bin/sh", "-c", "cat /proc/self/cgroup"]);
    s.limits.cgroup = Some(Cgroup { memory_mib: 64, cpu_percent: 100, tasks: 64 });
    let out = t.output(&s);
    assert!(out.stdout.contains(".scope"), "{}", out.stdout);
}
```

- [ ] **Step 2: Run; expect PASS or FAIL as appropriate.** Teardown should already pass (pdeathsig chain plus PID 1); if it passes, the test pins Review Focus 5. The cgroup test fails if the generic spawn lost the scope. Fix any failure.

- [ ] **Step 3:**
  - Drop `#[doc(hidden)]` from `pub mod sandbox`, and document the module (the layout and every requirement: Linux ≥ 5.12, `newuidmap`, subuid ≥ count, AppArmor profile, `pasta`).
  - README gets "Sandboxing any program" with a `Root::Overlay` + `nest` example.
  - CI `contract-x86_64` job:
    - `sudo apt-get install -y uidmap`;
    - `echo "$USER:200000:65536" | sudo tee -a /etc/subuid /etc/subgid`, plus a `grep` to verify;
    - `cargo test --test exec` after `--test sandbox`.

- [ ] **Step 4: Full suite in Lima and on macOS.**
  - macOS: `cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo test --all`.
  - Lima: the same, plus `cargo test --test sandbox`, `--test exec`, and `--test contract`, `--test network` and `--test pause` with the kernel env.
  - Expected: all PASS.

- [ ] **Step 5: Commit** `sandbox: document it, CI for the generic suite`.
