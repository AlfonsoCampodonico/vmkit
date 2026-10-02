//! Hostile-guest network tests (kiln spec §9.3, §11.5): every test runs against both backends.
//!
//! Needs what the contract suite needs, plus `pasta`, `ip` and `nft`, and the fixture
//! addresses from `testguest/net-fixture.sh` (run once per boot, with sudo):
//!   169.254.169.254  stands in for cloud metadata
//!   10.250.0.1       a private (RFC 1918) address on the host
//!   198.51.100.7     a host address outside the private ranges
//! Set VMKIT_TEST_NET=1 once they exist; VMKIT_REQUIRE_KVM_TESTS=1 makes skipping a failure.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use common::{Case, END};
use vmkit::net::{Cidr, Egress, GATEWAY, GUEST, PREFIX, PortForward, Protocol};
use vmkit::{Backend, NetSpec, Vm, VmSpec};

const METADATA: &str = "169.254.169.254";
const PRIVATE: &str = "10.250.0.1";
const HOST: &str = "198.51.100.7";
/// A source address the guest was not given.
const SPOOF: &str = "10.200.0.9/32";

fn net_case(backend: Backend) -> Option<Case> {
    if std::env::var_os("VMKIT_TEST_NET").is_none_or(|v| v != "1") {
        assert!(
            std::env::var_os("VMKIT_REQUIRE_KVM_TESTS").is_none_or(|v| v != "1"),
            "VMKIT_REQUIRE_KVM_TESTS is set but VMKIT_TEST_NET is not (run testguest/net-fixture.sh)"
        );
        return None;
    }
    Case::new(backend)
}

/// A host listener on every address that accepts and closes connections.
fn listener() -> u16 {
    let l = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            drop(s);
        }
    });
    port
}

/// A free host port for a forward.
fn free_port() -> u16 {
    TcpListener::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port()
}

/// The `net` guest: eth0 configured, then `extra` (probes, DNS, spoof, serve).
fn net_spec(c: &Case, net: NetSpec, extra: &[String]) -> VmSpec {
    let mut spec = c.spec("net");
    spec.cmdline.push(format!("vmkit.ip={GUEST}/{PREFIX}"));
    spec.cmdline.push(format!("vmkit.gw={GATEWAY}"));
    spec.cmdline.extend(extra.iter().cloned());
    spec.net = Some(net);
    spec
}

fn probes(addrs: &[&str], port: u16) -> Vec<String> {
    addrs.iter().map(|a| format!("vmkit.probe={a}:{port}")).collect()
}

/// The guest's verdict for one probe, e.g. `("tcp", "10.250.0.1:80")` -> `"open"`.
fn verdict(c: &Case, kind: &str, target: &str) -> String {
    let prefix = format!("VMKIT-PROBE {kind} {target} ");
    c.console()
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix).map(String::from))
        .unwrap_or_else(|| panic!("no result for {kind} {target}; console tail:\n{}", c.tail()))
}

fn dns(c: &Case, name: &str) -> String {
    let prefix = format!("VMKIT-DNS {name} ");
    c.console()
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix).map(String::from))
        .unwrap_or_else(|| panic!("no DNS result for {name}; console tail:\n{}", c.tail()))
}

fn restricted_egress_reaches_no_metadata_private_or_host_address(backend: Backend) {
    let Some(c) = net_case(backend) else { return };
    let port = listener();
    let mut extra = probes(&[METADATA, PRIVATE, HOST, &GATEWAY.to_string()], port);
    extra.push("vmkit.dns=localhost".into());
    c.run(&net_spec(&c, NetSpec::default(), &extra));
    for target in [METADATA, PRIVATE, HOST, &GATEWAY.to_string()] {
        assert_eq!(verdict(&c, "tcp", &format!("{target}:{port}")), "closed", "{target}");
    }
    assert_eq!(dns(&c, "localhost"), "ok", "DNS through the gateway");
}

fn allowed_destinations_are_reachable_and_spoofed_sources_are_not(backend: Backend) {
    let Some(c) = net_case(backend) else { return };
    let port = listener();
    let net = NetSpec {
        allow: vec![format!("{PRIVATE}/32").parse::<Cidr>().unwrap()],
        ..NetSpec::default()
    };
    let mut extra = probes(&[PRIVATE, METADATA], port);
    extra.push(format!("vmkit.spoof={SPOOF}"));
    c.run(&net_spec(&c, net, &extra));
    // The positive control: the path works, so the other verdicts are the policy's.
    assert_eq!(verdict(&c, "tcp", &format!("{PRIVATE}:{port}")), "open");
    assert_eq!(verdict(&c, "tcp", &format!("{METADATA}:{port}")), "closed");
    assert_eq!(verdict(&c, "spoofed", &format!("{PRIVATE}:{port}")), "closed");
}

fn deny_all_leaves_only_dns_and_open_removes_the_denies(backend: Backend) {
    let Some(c) = net_case(backend) else { return };
    let port = listener();
    let mut extra = probes(&[PRIVATE, HOST], port);
    extra.push("vmkit.dns=localhost".into());
    let deny_all = NetSpec {
        egress: Egress::DenyAll,
        ..NetSpec::default()
    };
    c.run(&net_spec(&c, deny_all, &extra));
    assert_eq!(verdict(&c, "tcp", &format!("{PRIVATE}:{port}")), "closed");
    assert_eq!(dns(&c, "localhost"), "ok");

    let Some(c) = net_case(backend) else { return };
    let open = NetSpec {
        egress: Egress::Open,
        ..NetSpec::default()
    };
    c.run(&net_spec(&c, open, &probes(&[HOST, METADATA], port)));
    assert_eq!(verdict(&c, "tcp", &format!("{HOST}:{port}")), "open");
    assert_eq!(verdict(&c, "tcp", &format!("{METADATA}:{port}")), "open");
}

/// An HTTP GET of `/` from `addr`, retried until the guest serves it.
fn fetch(addr: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let attempt = TcpStream::connect(addr).and_then(|mut s| {
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
            let mut body = String::new();
            s.read_to_string(&mut body)?;
            Ok(body)
        });
        match attempt {
            Ok(body) if body.contains("VMKIT-SERVED") => return body,
            other => assert!(Instant::now() < deadline, "{addr}: {other:?}"),
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn port_forwards_reach_the_guest_but_other_vms_do_not(backend: Backend) {
    let Some(server) = net_case(backend) else { return };
    let host_port = free_port();
    let net = NetSpec {
        forwards: vec![PortForward {
            protocol: Protocol::Tcp,
            host: host_port,
            guest: 8080,
        }],
        ..NetSpec::default()
    };
    let spec = net_spec(&server, net, &["vmkit.serve=8080".into(), "vmkit.hold=60".into()]);
    let mut vm: Box<dyn Vm> = server.vmm.create(&spec).expect("create");
    vm.start().expect("start");
    server.await_console("VMKIT-SERVING", 1);
    // Both pasta paths: spliced from host loopback, and through its interface.
    fetch(&format!("127.0.0.1:{host_port}"));
    fetch(&format!("{HOST}:{host_port}"));

    // Another VM reaches the forwarded port through none of the host's addresses.
    let Some(other) = net_case(backend) else { return };
    other.run(&net_spec(
        &other,
        NetSpec::default(),
        &probes(&[HOST, PRIVATE], host_port),
    ));
    for target in [HOST, PRIVATE] {
        assert_eq!(
            verdict(&other, "tcp", &format!("{target}:{host_port}")),
            "closed",
            "{target}"
        );
    }
    let vmm_pid = std::fs::read_to_string(vmkit::sandbox::pid_file(server.dir.path())).unwrap();
    vm.kill().unwrap();
    vm.wait_timeout(END).unwrap().expect("killed");
    // pasta lived in the VM's PID namespace, so it ended with the VMM.
    let netns = format!("/proc/{}/ns/net", vmm_pid.trim());
    let deadline = Instant::now() + Duration::from_secs(5);
    while pasta_for(&netns) {
        assert!(Instant::now() < deadline, "pasta outlived its VM");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Whether a pasta process is attached to `netns` (as named on its command line).
fn pasta_for(netns: &str) -> bool {
    std::fs::read_dir("/proc").unwrap().filter_map(|e| e.ok()).any(|e| {
        let cmdline = std::fs::read(e.path().join("cmdline")).unwrap_or_default();
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        args.first().is_some_and(|a| a.ends_with(b"pasta")) && args.contains(&netns.as_bytes())
    })
}

fn a_host_port_in_use_fails_with_pastas_message(backend: Backend) {
    let Some(c) = net_case(backend) else { return };
    let taken = TcpListener::bind("0.0.0.0:0").unwrap();
    let net = NetSpec {
        forwards: vec![PortForward {
            protocol: Protocol::Tcp,
            host: taken.local_addr().unwrap().port(),
            guest: 80,
        }],
        ..NetSpec::default()
    };
    let err = c.vmm.create(&net_spec(&c, net, &[])).err().expect("the port is taken");
    assert!(
        matches!(&err, vmkit::Error::EarlyExit(m) if m.contains("pasta")),
        "{err}"
    );
}

macro_rules! network {
    ($($name:ident),* $(,)?) => {
        mod firecracker {
            $( #[test] fn $name() { super::$name(vmkit::Backend::Firecracker) } )*
        }
        mod cloud_hypervisor {
            $( #[test] fn $name() { super::$name(vmkit::Backend::CloudHypervisor) } )*
        }
    };
}

network!(
    restricted_egress_reaches_no_metadata_private_or_host_address,
    allowed_destinations_are_reachable_and_spoofed_sources_are_not,
    deny_all_leaves_only_dns_and_open_removes_the_denies,
    port_forwards_reach_the_guest_but_other_vms_do_not,
    a_host_port_in_use_fails_with_pastas_message,
);
