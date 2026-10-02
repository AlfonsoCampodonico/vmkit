//! Guest networking (kiln spec §9.3): the VM's own net namespace with a tap, an
//! nftables policy and `pasta` for unprivileged egress through host sockets.

use std::net::Ipv4Addr;

/// The tap device in the VM's namespace.
pub const TAP: &str = "tap0";
/// The namespace's address on the tap: the guest's gateway and DNS server.
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(172, 30, 0, 1);
/// The guest's address. Every VM has its own namespace, so addresses never collide.
pub const GUEST: Ipv4Addr = Ipv4Addr::new(172, 30, 0, 2);
/// The prefix length of the tap network.
pub const PREFIX: u8 = 30;
/// The guest's MAC address (one VM per namespace, so it never collides either).
pub const GUEST_MAC: &str = "06:00:ac:1e:00:02";
