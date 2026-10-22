//! The attached-tap mode (kiln-shim spec §3.2): the VMM stays in the caller's network
//! namespace and uses a tap the caller made there. Every test runs against both backends.
//!
//! Needs what the contract suite needs, run inside the namespace `testguest/attach-fixture.sh`
//! makes (with sudo), as the user who owns its tap; set VMKIT_TEST_ATTACH=1 there.
//! VMKIT_REQUIRE_KVM_TESTS=1 makes skipping a failure.

mod common;

use std::net::{Ipv4Addr, TcpListener};
use std::sync::Mutex;

use common::Case;
use vmkit::{Backend, TapAttach};

/// The fixture's tap and its address, the guest's gateway.
const TAP: &str = "vmktap0";
const HOST_SIDE: Ipv4Addr = Ipv4Addr::new(10, 251, 0, 1);
/// One VM at a time holds the fixture's tap (a second open is `EBUSY`).
static TAP_HELD: Mutex<()> = Mutex::new(());

fn attach_case(backend: Backend) -> Option<Case> {
    if std::env::var_os("VMKIT_TEST_ATTACH").is_none_or(|v| v != "1") {
        assert!(
            std::env::var_os("VMKIT_REQUIRE_KVM_TESTS").is_none_or(|v| v != "1"),
            "VMKIT_REQUIRE_KVM_TESTS is set but VMKIT_TEST_ATTACH is not (run testguest/attach-fixture.sh)"
        );
        return None;
    }
    Case::new(backend)
}

/// The guest's verdict for a probe of `target`.
fn verdict(c: &Case, target: &str) -> String {
    let prefix = format!("VMKIT-PROBE tcp {target} ");
    c.console()
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix).map(String::from))
        .unwrap_or_else(|| panic!("no result for {target}; console tail:\n{}", c.tail()))
}

fn the_guest_reaches_the_callers_namespace_through_the_attached_tap(backend: Backend) {
    let _tap = TAP_HELD.lock().unwrap_or_else(|e| e.into_inner());
    let Some(c) = attach_case(backend) else { return };
    // Only this namespace has the address, so an open verdict means the VMM used its tap.
    let l = TcpListener::bind((HOST_SIDE, 0)).expect("run inside the fixture namespace");
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            drop(s);
        }
    });
    let mut spec = c.spec("net");
    spec.cmdline.push("vmkit.ip=10.251.0.2/24".into());
    spec.cmdline.push(format!("vmkit.gw={HOST_SIDE}"));
    spec.cmdline.push(format!("vmkit.probe={HOST_SIDE}:{port}"));
    spec.tap = Some(TapAttach {
        tap: TAP.into(),
        mac: "02:00:0a:fb:00:02".into(),
    });
    c.run(&spec);
    assert_eq!(verdict(&c, &format!("{HOST_SIDE}:{port}")), "open");
}

macro_rules! attach {
    ($($name:ident),* $(,)?) => {
        mod firecracker {
            $( #[test] fn $name() { super::$name(vmkit::Backend::Firecracker) } )*
        }
        mod cloud_hypervisor {
            $( #[test] fn $name() { super::$name(vmkit::Backend::CloudHypervisor) } )*
        }
    };
}

attach!(the_guest_reaches_the_callers_namespace_through_the_attached_tap);
