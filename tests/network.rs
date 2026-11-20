//! Hostile-guest network tests (kiln spec §9.3, §11.5): every test runs against both backends.
//!
//! Needs what the contract suite needs, plus `pasta`, `ip` and `nft`, and the fixture
//! addresses from `testguest/net-fixture.sh` (run once per boot, with sudo):
//!   169.254.169.254  stands in for cloud metadata
//!   10.250.0.1       a private (RFC 1918) address on the host
//!   198.51.100.7     a host address outside the private ranges
//!   fd00:ec2::254    stands in for cloud metadata over IPv6 (AWS's address)
//!   fd00:250::1      a private (ULA) IPv6 address on the host
//!   3ffe::7          a host IPv6 address outside the special ranges
//! and, on a host without IPv6, a stand-in default route for pasta to copy.
//! Set VMKIT_TEST_NET=1 once they exist; VMKIT_REQUIRE_KVM_TESTS=1 makes skipping a failure.

mod common;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use common::{Case, END};
use vmkit::net::{Cidr, Egress, GATEWAY, GATEWAY6, GUEST, GUEST6, PREFIX, PREFIX6, PortForward, Protocol};
use vmkit::{Backend, EgressGate, NetSpec, Vm, VmSpec};

const METADATA: &str = "169.254.169.254";
const PRIVATE: &str = "10.250.0.1";
const HOST: &str = "198.51.100.7";
const METADATA6: &str = "fd00:ec2::254";
const PRIVATE6: &str = "fd00:250::1";
const HOST6: &str = "3ffe::7";
/// Source addresses the guest was not given.
const SPOOF: &str = "10.200.0.9/32";
const SPOOF6: &str = "fd76:6d6b:6974::99/64";

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

/// A host listener on every address, IPv4 and IPv6, that accepts and closes connections.
fn listener() -> u16 {
    let l = TcpListener::bind("[::]:0").unwrap();
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
    spec.cmdline.push(format!("vmkit.ip6={GUEST6}/{PREFIX6}"));
    spec.cmdline.push(format!("vmkit.gw6={GATEWAY6}"));
    spec.cmdline.extend(extra.iter().cloned());
    spec.net = Some(NetSpec { ipv6: true, ..net });
    spec
}

/// `addr:port`, with an IPv6 address in brackets.
fn at(addr: &str, port: u16) -> String {
    SocketAddr::new(addr.parse::<IpAddr>().unwrap(), port).to_string()
}

fn probes(addrs: &[&str], port: u16) -> Vec<String> {
    addrs.iter().map(|a| format!("vmkit.probe={}", at(a, port))).collect()
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
    dns_labelled(c, "VMKIT-DNS", name)
}

/// A DNS result under `label` (`VMKIT-DNS`, or `VMKIT-DNS-<round>` for a later round).
fn dns_labelled(c: &Case, label: &str, name: &str) -> String {
    let prefix = format!("{label} {name} ");
    c.console()
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix).map(String::from))
        .unwrap_or_else(|| panic!("no DNS result for {name}; console tail:\n{}", c.tail()))
}

fn restricted_egress_reaches_no_metadata_private_or_host_address(backend: Backend) {
    let Some(c) = net_case(backend) else { return };
    let port = listener();
    let (gateway, gateway6) = (GATEWAY.to_string(), GATEWAY6.to_string());
    let targets = [METADATA, PRIVATE, HOST, &gateway, METADATA6, PRIVATE6, HOST6, &gateway6];
    let mut extra = probes(&targets, port);
    extra.push("vmkit.dns=localhost".into());
    c.run(&net_spec(&c, NetSpec::default(), &extra));
    for target in targets {
        assert_eq!(verdict(&c, "tcp", &at(target, port)), "closed", "{target}");
    }
    assert_eq!(dns(&c, "localhost"), "ok", "DNS through the gateway");
}

fn allowed_destinations_are_reachable_and_spoofed_sources_are_not(backend: Backend) {
    let Some(c) = net_case(backend) else { return };
    let port = listener();
    let net = NetSpec {
        allow: vec![PRIVATE.parse::<Cidr>().unwrap(), PRIVATE6.parse::<Cidr>().unwrap()],
        ..NetSpec::default()
    };
    let mut extra = probes(&[PRIVATE, METADATA, PRIVATE6, METADATA6], port);
    extra.push(format!("vmkit.spoof={SPOOF}"));
    extra.push(format!("vmkit.spoof6={SPOOF6}"));
    c.run(&net_spec(&c, net, &extra));
    // The positive controls: the path works, so the other verdicts are the policy's.
    for (private, metadata) in [(PRIVATE, METADATA), (PRIVATE6, METADATA6)] {
        assert_eq!(verdict(&c, "tcp", &at(private, port)), "open", "{private}");
        assert_eq!(verdict(&c, "tcp", &at(metadata, port)), "closed", "{metadata}");
        assert_eq!(verdict(&c, "spoofed", &at(private, port)), "closed", "{private}");
    }
}

fn deny_all_leaves_only_dns_and_open_removes_the_denies(backend: Backend) {
    let Some(c) = net_case(backend) else { return };
    let port = listener();
    let mut extra = probes(&[PRIVATE, HOST, PRIVATE6, HOST6], port);
    extra.push("vmkit.dns=localhost".into());
    let deny_all = NetSpec {
        egress: Egress::DenyAll,
        ..NetSpec::default()
    };
    c.run(&net_spec(&c, deny_all, &extra));
    for target in [PRIVATE, HOST, PRIVATE6, HOST6] {
        assert_eq!(verdict(&c, "tcp", &at(target, port)), "closed", "{target}");
    }
    assert_eq!(dns(&c, "localhost"), "ok");

    // Allow exceptions apply under deny-all.
    let Some(c) = net_case(backend) else { return };
    let deny_all_but_private = NetSpec {
        egress: Egress::DenyAll,
        allow: vec![PRIVATE.parse::<Cidr>().unwrap(), PRIVATE6.parse::<Cidr>().unwrap()],
        ..NetSpec::default()
    };
    c.run(&net_spec(
        &c,
        deny_all_but_private,
        &probes(&[PRIVATE, HOST, PRIVATE6, HOST6], port),
    ));
    for (private, host) in [(PRIVATE, HOST), (PRIVATE6, HOST6)] {
        assert_eq!(verdict(&c, "tcp", &at(private, port)), "open", "{private}");
        assert_eq!(verdict(&c, "tcp", &at(host, port)), "closed", "{host}");
    }

    let Some(c) = net_case(backend) else { return };
    let open = NetSpec {
        egress: Egress::Open,
        ..NetSpec::default()
    };
    c.run(&net_spec(&c, open, &probes(&[HOST, METADATA, HOST6, METADATA6], port)));
    for target in [HOST, METADATA, HOST6, METADATA6] {
        assert_eq!(verdict(&c, "tcp", &at(target, port)), "open", "{target}");
    }
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
            address: Ipv4Addr::UNSPECIFIED,
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
    let netns = netns_of(server.dir.path()).expect("the VMM's pid file");
    assert!(pasta_for(&netns), "no pasta attached to {netns} while the VM runs");
    vm.kill().unwrap();
    vm.wait_timeout(END).unwrap().expect("killed");
    // pasta lived in the VM's PID namespace, so it ended with the VMM.
    assert_pasta_gone(&netns);
}

fn a_forward_bound_to_loopback_is_reachable_only_there(backend: Backend) {
    let Some(server) = net_case(backend) else { return };
    let host_port = free_port();
    let net = NetSpec {
        forwards: vec![PortForward {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::LOCALHOST,
            host: host_port,
            guest: 8080,
        }],
        ..NetSpec::default()
    };
    let spec = net_spec(&server, net, &["vmkit.serve=8080".into(), "vmkit.hold=60".into()]);
    let mut vm: Box<dyn Vm> = server.vmm.create(&spec).expect("create");
    vm.start().expect("start");
    server.await_console("VMKIT-SERVING", 1);
    fetch(&format!("127.0.0.1:{host_port}"));
    // pasta listens on loopback only: the host's other addresses refuse the connection.
    for addr in [HOST, PRIVATE] {
        let err = TcpStream::connect_timeout(&format!("{addr}:{host_port}").parse().unwrap(), Duration::from_secs(5))
            .expect_err("a loopback forward answered on another address");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused, "{addr}: {err}");
    }
    vm.kill().unwrap();
    vm.wait_timeout(END).unwrap().expect("killed");
}

/// Connects to the guest's knock listener through `addr` until it answers for `round`, which
/// starts that round of probes.
fn knock(addr: &str, round: u32) {
    let want = format!("VMKIT-KNOCK {round}");
    let deadline = Instant::now() + END;
    loop {
        let attempt = TcpStream::connect(addr).and_then(|mut s| {
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut text = String::new();
            s.read_to_string(&mut text)?;
            Ok(text)
        });
        match attempt {
            Ok(text) if text.contains(&want) => return,
            other => assert!(Instant::now() < deadline, "knock {round} at {addr}: {other:?}"),
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// kiln's build steps: one VM whose egress is closed and reopened while it runs.
fn egress_closes_and_reopens_at_runtime(backend: Backend) {
    let Some(c) = net_case(backend) else { return };
    let port = listener();
    let knock_port = free_port();
    let net = NetSpec {
        // The knocks come in through pasta's interface, so forwards are shown to work while closed.
        forwards: vec![PortForward {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::UNSPECIFIED,
            host: knock_port,
            guest: 7000,
        }],
        // Restricted denies the host's addresses: reaching them shows the allow list is back.
        allow: vec![HOST.parse::<Cidr>().unwrap(), HOST6.parse::<Cidr>().unwrap()],
        ..NetSpec::default()
    };
    let gates = [
        EgressGate::Closed,
        EgressGate::Policy,
        EgressGate::Closed,
        EgressGate::Policy,
    ];
    let mut extra = probes(&[HOST, HOST6], port);
    extra.push("vmkit.dns=localhost".into());
    extra.push(format!("vmkit.rounds={}", gates.len()));
    extra.push("vmkit.knock=7000".into());
    let mut vm: Box<dyn Vm> = c.vmm.create(&net_spec(&c, net, &extra)).expect("create");
    // Before start the namespace exists already: the gate can be set (and reset) then too.
    vm.set_egress(EgressGate::Closed).expect("close before start");
    vm.set_egress(EgressGate::Policy).expect("reopen before start");
    vm.start().expect("start");
    c.await_console("VMKIT-KNOCK-WAIT 1", 1);
    // Round 0, at boot under the VM's own policy: the allowed addresses and DNS.
    for target in [HOST, HOST6] {
        assert_eq!(verdict(&c, "tcp", &at(target, port)), "open", "{target}");
    }
    assert_eq!(dns(&c, "localhost"), "ok");
    for (i, gate) in gates.into_iter().enumerate() {
        let round = i as u32 + 1;
        vm.set_egress(gate).expect("set_egress");
        // Idempotent: setting the same gate again changes nothing.
        vm.set_egress(gate).expect("set_egress again");
        knock(&format!("{HOST}:{knock_port}"), round);
        c.await_console(&format!("VMKIT-ROUND-DONE {round}"), 1);
        let (want, dns_want) = match gate {
            EgressGate::Closed => ("closed", "fail"),
            EgressGate::Policy => ("open", "ok"),
        };
        for target in [HOST, HOST6] {
            assert_eq!(
                verdict(&c, &format!("tcp-{round}"), &at(target, port)),
                want,
                "round {round} ({gate:?}): {target}"
            );
        }
        assert_eq!(
            dns_labelled(&c, &format!("VMKIT-DNS-{round}"), "localhost"),
            dns_want,
            "round {round} ({gate:?}): DNS"
        );
    }
    vm.wait_timeout(END)
        .unwrap()
        .unwrap_or_else(|| panic!("VM did not end; console tail:\n{}", c.tail()));
    let err = vm.set_egress(EgressGate::Closed).expect_err("the VM has ended");
    assert!(matches!(err, vmkit::Error::EgressFailed(_)), "{err}");
}

/// Only a VM with a network of vmkit's own has an egress to set.
fn a_vm_without_its_own_network_has_no_egress_to_set(backend: Backend) {
    let Some(c) = net_case(backend) else { return };
    let mut vm: Box<dyn Vm> = c.vmm.create(&c.spec("up")).expect("create");
    let err = vm.set_egress(EgressGate::Closed).expect_err("no NIC");
    assert!(
        matches!(&err, vmkit::Error::EgressUnavailable(m) if m.contains("no NIC")),
        "{err}"
    );
}

/// pasta copies the host's outbound address into the namespace, so an exception for it
/// alone could never work: refused. (The fixture addresses on `lo` are not copied: the
/// allow cases above reach them.)
fn an_allow_entry_for_the_hosts_outbound_address_is_refused(backend: Backend) {
    let Some(c) = net_case(backend) else { return };
    let outbound = vmkit::net::outbound_address().expect("a default route");
    let net = NetSpec {
        egress: Egress::DenyAll,
        allow: vec![Cidr::new(outbound, 32).unwrap()],
        ..NetSpec::default()
    };
    let err = c.vmm.create(&net_spec(&c, net, &[])).err().expect("refused");
    assert!(
        matches!(&err, vmkit::Error::InvalidSpec(m) if m.contains(&format!("is the host's own address {outbound}"))),
        "{err}"
    );
}

/// The network namespace path of the VMM recorded in `run_dir`, if it got that far.
fn netns_of(run_dir: &std::path::Path) -> Option<String> {
    let pid = std::fs::read_to_string(vmkit::sandbox::pid_file(run_dir)).ok()?;
    Some(format!("/proc/{}/ns/net", pid.trim()))
}

/// Waits (briefly) for every pasta attached to `netns` to exit.
fn assert_pasta_gone(netns: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while pasta_for(netns) {
        assert!(Instant::now() < deadline, "pasta outlived its VM ({netns})");
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
            address: Ipv4Addr::UNSPECIFIED,
            host: taken.local_addr().unwrap().port(),
            guest: 80,
        }],
        ..NetSpec::default()
    };
    let started = Instant::now();
    let err = c.vmm.create(&net_spec(&c, net, &[])).err().expect("the port is taken");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "create hung for {:?}",
        started.elapsed()
    );
    // pasta's own message, not just the helper's wrapper text.
    assert!(
        matches!(&err, vmkit::Error::EarlyExit(m) if m.contains("pasta") && m.contains("Address already in use")),
        "{err}"
    );
    // No pasta is left behind by the failed VM.
    if let Some(netns) = netns_of(c.dir.path()) {
        assert_pasta_gone(&netns);
    }
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
    a_forward_bound_to_loopback_is_reachable_only_there,
    an_allow_entry_for_the_hosts_outbound_address_is_refused,
    egress_closes_and_reopens_at_runtime,
    a_vm_without_its_own_network_has_no_egress_to_set,
);
