//! Guest networking (kiln spec §9.3): the VM's own net namespace with a tap, an
//! nftables policy and `pasta` for unprivileged egress through host sockets.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The tap device in the VM's namespace.
pub const TAP: &str = "tap0";
/// The namespace's address on the tap: the guest's gateway and DNS server.
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(172, 30, 0, 1);
/// The guest's address. Every VM has its own namespace, so addresses never collide.
pub const GUEST: Ipv4Addr = Ipv4Addr::new(172, 30, 0, 2);
/// The prefix length of the tap network.
pub const PREFIX: u8 = 30;
/// The namespace's IPv6 address on the tap, the guest's IPv6 gateway (in the ULA
/// `fd76:6d6b:6974::/48`, whose global ID spells `vmkit`). DNS stays on [`GATEWAY`].
pub const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0xfd76, 0x6d6b, 0x6974, 0, 0, 0, 0, 1);
/// The guest's IPv6 address; the namespace masquerades it, as it does [`GUEST`].
pub const GUEST6: Ipv6Addr = Ipv6Addr::new(0xfd76, 0x6d6b, 0x6974, 0, 0, 0, 0, 2);
/// The prefix length of the tap network's IPv6 side.
pub const PREFIX6: u8 = 64;
/// The guest's MAC address (one VM per namespace, so it never collides either).
pub const GUEST_MAC: &str = "06:00:ac:1e:00:02";
/// `pasta`'s interface in the VM's namespace.
pub(crate) const EGRESS: &str = "egress0";
/// Where `pasta` answers DNS in the namespace; guest queries to the gateway are sent here.
pub(crate) const DNS_FORWARD: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 53);
/// The DNS server for programs in a namespace with egress but no tap (`resolv.conf`'s nameserver).
pub const NAMESERVER: Ipv4Addr = DNS_FORWARD;

/// Destinations the default `restricted` egress denies, besides the host's own addresses.
const RESTRICTED: [&str; 10] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/3",
];

/// IPv6 destinations the default `restricted` egress denies, besides the host's own addresses
/// and connected prefixes: everything outside global unicast `2000::/3` (loopback, unspecified,
/// IPv4-mapped and -compatible, NAT64, discard, SRv6, ULA, link-local, site-local, multicast and
/// unallocated space), and inside it the IETF protocol assignments (Teredo, benchmarking),
/// documentation and 6to4 ranges. Those that embed an IPv4 address could reach what
/// [`RESTRICTED`] denies.
const RESTRICTED6: [&str; 7] = [
    "::/3",
    "4000::/2",
    "8000::/1",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
];

/// An IPv4 or IPv6 network such as `10.0.0.0/8` or `2001:db8::/32`; a bare address is a
/// `/32` or a `/128`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

/// `addr` with every bit after the first `prefix` cleared.
fn network(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
    }
}

impl Cidr {
    /// The network containing `addr` (host bits are cleared).
    pub fn new(addr: impl Into<IpAddr>, prefix: u8) -> Option<Self> {
        let addr = addr.into();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return None;
        }
        Some(Self {
            addr: network(addr, prefix),
            prefix,
        })
    }

    /// The network address (host bits cleared).
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether this is an IPv6 network.
    pub fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }

    /// Whether `addr` is in this network (never across address families).
    pub fn contains(&self, addr: IpAddr) -> bool {
        addr.is_ipv6() == self.is_ipv6() && network(addr, self.prefix) == self.addr
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("{s:?} is not an IP address or CIDR");
        let (addr, prefix) = s.split_once('/').map_or((s, None), |(a, p)| (a, Some(p)));
        let addr: IpAddr = addr.parse().map_err(|_| bad())?;
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().map_err(|_| bad())?,
            None if addr.is_ipv4() => 32,
            None => 128,
        };
        Cidr::new(addr, prefix).ok_or_else(bad)
    }
}

impl TryFrom<String> for Cidr {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        s.parse()
    }
}

impl From<Cidr> for String {
    fn from(c: Cidr) -> String {
        c.to_string()
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// What the guest may reach (`--egress`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Egress {
    /// Everything except link-local (cloud metadata), CGNAT, RFC 1918, `0/8`,
    /// loopback, multicast and reserved ranges, and the host's own addresses.
    #[default]
    Restricted,
    /// Nothing but DNS.
    DenyAll,
    /// Everything. Callers should warn.
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn nft(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// Host port `host`, listened on at `address`, reaches guest port `guest`
/// (`-p ADDRESS:HOST:GUEST/proto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForward {
    pub protocol: Protocol,
    /// The host address `pasta` listens on: [`Ipv4Addr::LOCALHOST`] keeps the port to this
    /// host, [`Ipv4Addr::UNSPECIFIED`] listens on every address. It must be one of the
    /// host's own addresses (or unspecified); `pasta` fails to start otherwise.
    pub address: Ipv4Addr,
    pub host: u16,
    pub guest: u16,
}

/// A network interface for the guest, `eth0` at [`GUEST`]/[`PREFIX`] via [`GATEWAY`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NetSpec {
    pub egress: Egress,
    /// Exceptions to `Restricted` and `DenyAll`; ignored under `Egress::Open`.
    pub allow: Vec<Cidr>,
    pub forwards: Vec<PortForward>,
}

impl NetSpec {
    /// Rejects forwards the namespace cannot hold: port 0, or a host port used twice. A
    /// port is used twice even on two addresses: the namespace sees only the port.
    pub(crate) fn check(&self) -> Result<(), String> {
        for (i, f) in self.forwards.iter().enumerate() {
            if f.host == 0 || f.guest == 0 {
                return Err(format!("port forward {}:{} uses port 0", f.host, f.guest));
            }
            if self.forwards[..i]
                .iter()
                .any(|g| g.protocol == f.protocol && g.host == f.host)
            {
                return Err(format!("host port {} is forwarded twice", f.host));
            }
        }
        Ok(())
    }

    /// Rejects an `allow` entry that is only one of `copied`, the host addresses `pasta
    /// --config-net` copies into the VM's namespace ([`outbound_address`]): packets to
    /// them never leave the namespace, so such an exception could never work. A wider
    /// entry that includes one still works for its other addresses; callers may warn.
    /// Under `Open`, `allow` is unused and nothing is checked.
    pub fn check_allow(&self, copied: &[IpAddr]) -> Result<(), String> {
        if self.egress == Egress::Open {
            return Ok(());
        }
        for c in &self.allow {
            if let Some(a) = copied
                .iter()
                .find(|a| Some(*c) == Cidr::new(**a, if a.is_ipv4() { 32 } else { 128 }))
            {
                return Err(format!(
                    "the egress exception {c} is the host's own address {a}, which the VM can never reach \
                     (pasta gives the VM's namespace that address)"
                ));
            }
        }
        Ok(())
    }
}

/// The `elements = { ... }` of the deny and allow sets, per address family.
struct Sets {
    deny: String,
    allow: String,
    deny6: String,
    allow6: String,
}

/// The sets for `spec`; `host` lists the host's own addresses and the prefixes it reaches
/// directly, which `Restricted` denies.
fn sets(spec: &NetSpec, host: &[Cidr]) -> Sets {
    let set = |items: Vec<String>| {
        if items.is_empty() {
            String::new()
        } else {
            format!(" elements = {{ {} }}", items.join(", "))
        }
    };
    let of = |cidrs: &[Cidr], v6: bool| -> Vec<String> {
        cidrs
            .iter()
            .filter(|c| c.is_ipv6() == v6)
            .map(Cidr::to_string)
            .collect()
    };
    let (deny, deny6): (Vec<String>, Vec<String>) = match spec.egress {
        Egress::Restricted => (
            RESTRICTED
                .iter()
                .map(|s| s.to_string())
                .chain(of(host, false))
                .collect(),
            RESTRICTED6
                .iter()
                .map(|s| s.to_string())
                .chain(of(host, true))
                .collect(),
        ),
        Egress::DenyAll => (vec!["0.0.0.0/0".into()], vec!["::/0".into()]),
        Egress::Open => (Vec::new(), Vec::new()),
    };
    let allow: &[Cidr] = match spec.egress {
        Egress::Open => &[],
        _ => &spec.allow,
    };
    Sets {
        deny: set(deny),
        allow: set(of(allow, false)),
        deny6: set(deny6),
        allow6: set(of(allow, true)),
    }
}

/// The nftables ruleset for a namespace without a tap, whose own processes reach out through
/// `pasta`: loopback and DNS at [`NAMESERVER`] are allowed, then the allow set, then the deny
/// set; IPv6 is dropped (so are IPv6 `allow` entries) and nothing new comes in.
#[doc(hidden)]
pub fn egress_ruleset(spec: &NetSpec, host: &[Cidr]) -> String {
    let Sets { deny, allow, .. } = sets(spec, host);
    format!(
        "table inet vmkit {{
  set deny {{ type ipv4_addr; flags interval; auto-merge;{deny} }}
  set allow {{ type ipv4_addr; flags interval; auto-merge;{allow} }}
  chain output {{
    type filter hook output priority filter; policy drop;
    oifname \"lo\" accept
    meta nfproto ipv6 drop
    ct state established,related accept
    ip daddr {NAMESERVER} udp dport 53 accept
    ip daddr {NAMESERVER} tcp dport 53 accept
    oifname \"{EGRESS}\" ip daddr @allow accept
    oifname \"{EGRESS}\" ip daddr @deny drop
    oifname \"{EGRESS}\" accept
  }}
  chain input {{
    type filter hook input priority filter; policy drop;
    iifname \"lo\" accept
    ct state established,related accept
  }}
}}
"
    )
}

/// The nftables ruleset for the VM's namespace. `host` lists the host's own addresses and
/// the IPv6 prefixes it reaches directly, which `Restricted` denies (pasta would otherwise
/// reach them through host sockets).
///
/// `forward` polices the guest in both address families. `input` takes nothing new from the
/// guest but its neighbour solicitations for the gateway. `local_out` stops the namespace's
/// own processes (the VMM) from opening any connection through pasta; their replies to
/// forwarded connections are not new, and spliced forwards leave through loopback and the
/// tap, not `egress0`.
#[doc(hidden)]
pub fn ruleset(spec: &NetSpec, host: &[Cidr]) -> String {
    let Sets {
        deny,
        allow,
        deny6,
        allow6,
    } = sets(spec, host);
    let mut prerouting = String::new();
    let mut output = String::new();
    for proto in ["udp", "tcp"] {
        prerouting += &format!("    iifname \"{TAP}\" ip daddr {GATEWAY} {proto} dport 53 dnat ip to {DNS_FORWARD}\n");
    }
    for f in &spec.forwards {
        let (p, h, g) = (f.protocol.nft(), f.host, f.guest);
        // pasta delivers a forwarded connection on its interface, or (when it splices a
        // connection from host loopback) as a local connection to the namespace's address.
        prerouting += &format!("    iifname != \"{TAP}\" fib daddr type local {p} dport {h} dnat ip to {GUEST}:{g}\n");
        output += &format!("    fib daddr type local {p} dport {h} dnat ip to {GUEST}:{g}\n");
    }
    format!(
        "table inet vmkit {{
  set deny {{ type ipv4_addr; flags interval; auto-merge;{deny} }}
  set allow {{ type ipv4_addr; flags interval; auto-merge;{allow} }}
  set deny6 {{ type ipv6_addr; flags interval; auto-merge;{deny6} }}
  set allow6 {{ type ipv6_addr; flags interval; auto-merge;{allow6} }}
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
{prerouting}  }}
  chain output {{
    type nat hook output priority dstnat; policy accept;
{output}  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname \"{EGRESS}\" masquerade
    oifname \"{TAP}\" ip saddr 127.0.0.0/8 masquerade
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    iifname \"{TAP}\" ip saddr != {GUEST} drop
    iifname \"{TAP}\" ip6 saddr != {GUEST6} drop
    ct state established,related accept
    ct status dnat accept
    iifname \"{TAP}\" oifname \"{EGRESS}\" ip daddr @allow accept
    iifname \"{TAP}\" oifname \"{EGRESS}\" ip daddr @deny drop
    iifname \"{TAP}\" oifname \"{EGRESS}\" ip6 daddr @allow6 accept
    iifname \"{TAP}\" oifname \"{EGRESS}\" ip6 daddr @deny6 drop
    iifname \"{TAP}\" oifname \"{EGRESS}\" accept
  }}
  chain input {{
    type filter hook input priority filter; policy accept;
    iifname \"{TAP}\" ct state established,related accept
    iifname \"{TAP}\" ip6 saddr {GUEST6} ip6 hoplimit 255 icmpv6 type nd-neighbor-solicit accept
    iifname \"{TAP}\" drop
  }}
  chain local_out {{
    type filter hook output priority filter; policy accept;
    oifname \"{EGRESS}\" ct state new drop
  }}
}}
",
    )
}

/// `pasta` options, without the namespace to attach to.
#[doc(hidden)]
pub fn pasta_args(spec: &NetSpec) -> Vec<String> {
    // One `--tcp-ports ADDRESS/PORT` per forward: pasta binds each to its own address.
    let ports = |flag: &str, p: Protocol| {
        let list: Vec<String> = spec
            .forwards
            .iter()
            .filter(|f| f.protocol == p)
            .map(|f| format!("{}/{}", f.address, f.host))
            .collect();
        let list = if list.is_empty() {
            vec!["none".to_string()]
        } else {
            list
        };
        list.into_iter().flat_map(|l| [flag.to_string(), l]).collect::<Vec<_>>()
    };
    let mut args: Vec<String> = [
        "--config-net",
        "--ns-ifname",
        EGRESS,
        "--ipv4-only",
        // Host loopback services stay unreachable from the namespace.
        "--no-map-gw",
        "--tcp-ns",
        "none",
        "--udp-ns",
        "none",
        "--dns-forward",
        &DNS_FORWARD.to_string(),
        "--quiet",
    ]
    .map(String::from)
    .to_vec();
    args.extend(ports("--tcp-ports", Protocol::Tcp));
    args.extend(ports("--udp-ports", Protocol::Udp));
    args
}

/// The host's address on its default route (the source address of outbound traffic),
/// which `pasta --config-net` copies into the VM's namespace, so the guest can never
/// reach it ([`NetSpec::check_allow`]). `None` without a default route. No packet is sent.
pub fn outbound_address() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    // TEST-NET-1: routed by the default route, never by a more specific one.
    s.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(a) if !a.is_unspecified() => Some(a),
        _ => None,
    }
}

/// The host's local IPv4 addresses, from `/proc/net/fib_trie`.
pub(crate) fn host_addresses(fib_trie: &str) -> Vec<Ipv4Addr> {
    let mut found = Vec::new();
    let mut last: Option<Ipv4Addr> = None;
    for line in fib_trie.lines() {
        let line = line.trim();
        if let Some(addr) = line.strip_prefix("|-- ") {
            last = addr.parse().ok();
        } else if line == "/32 host LOCAL" {
            if let Some(a) = last.filter(|a| !found.contains(a)) {
                found.push(a);
            }
        }
    }
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_egress_ruleset_polices_the_namespaces_own_traffic() {
        let r = egress_ruleset(&NetSpec::default(), &["192.168.5.15/32".parse().unwrap()]);
        assert!(
            r.contains("type filter hook output priority filter; policy drop;"),
            "{r}"
        );
        assert!(r.contains("192.168.5.15"));
        assert!(r.contains("169.254.0.0/16"));
        assert!(r.contains(&format!("ip daddr {NAMESERVER} udp dport 53 accept")));
        assert!(!r.contains(TAP), "a bare namespace has no tap");
        let open = egress_ruleset(
            &NetSpec {
                egress: Egress::Open,
                ..Default::default()
            },
            &[],
        );
        assert!(!open.contains("169.254.0.0/16"));
        let allowed = egress_ruleset(
            &NetSpec {
                allow: vec!["198.51.100.7".parse().unwrap()],
                ..Default::default()
            },
            &[],
        );
        assert!(allowed.contains("198.51.100.7/32"), "{allowed}");
    }

    #[test]
    fn cidrs_parse_and_normalise() {
        assert_eq!("10.1.2.3/8".parse::<Cidr>().unwrap().to_string(), "10.0.0.0/8");
        assert_eq!("1.2.3.4".parse::<Cidr>().unwrap().to_string(), "1.2.3.4/32");
        assert_eq!("0.0.0.0/0".parse::<Cidr>().unwrap().to_string(), "0.0.0.0/0");
        let c = "10.1.2.3/8".parse::<Cidr>().unwrap();
        assert_eq!((c.addr(), c.prefix()), (IpAddr::from([10, 0, 0, 0]), 8));
        for bad in [
            "1.2.3.4/33",
            "1.2.3/8",
            "x",
            "1.2.3.4/",
            "::1/129",
            "fe80::/",
            "[::1]/128",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
    }

    #[test]
    fn cidrs_may_be_ipv6() {
        assert_eq!("2001:db8:1::1/32".parse::<Cidr>().unwrap().to_string(), "2001:db8::/32");
        assert_eq!("::1".parse::<Cidr>().unwrap().to_string(), "::1/128");
        assert_eq!("::/0".parse::<Cidr>().unwrap().to_string(), "::/0");
        let c: Cidr = "fd00::/8".parse().unwrap();
        assert!(c.is_ipv6() && !"10.0.0.0/8".parse::<Cidr>().unwrap().is_ipv6());
        assert!(c.contains("fd00:ec2::254".parse().unwrap()));
        assert!(!c.contains("fe80::1".parse().unwrap()));
        // Never across families: ::/0 does not contain 0.0.0.0, nor 0.0.0.0/0 an IPv6 address.
        assert!(!"::/0".parse::<Cidr>().unwrap().contains("1.2.3.4".parse().unwrap()));
        assert!(!"0.0.0.0/0".parse::<Cidr>().unwrap().contains("::1".parse().unwrap()));
        assert!(Cidr::new(Ipv6Addr::LOCALHOST, 129).is_none());
        assert_eq!(
            Cidr::new(Ipv6Addr::LOCALHOST, 128).unwrap().addr(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn restricted_denies_the_private_ranges_and_the_host() {
        let r = ruleset(&NetSpec::default(), &["192.168.5.15/32".parse().unwrap()]);
        for range in RESTRICTED {
            assert!(r.contains(range), "{range} missing:\n{r}");
        }
        assert!(r.contains("192.168.5.15"), "{r}");
        assert!(
            r.contains("set allow { type ipv4_addr; flags interval; auto-merge; }"),
            "{r}"
        );
    }

    #[test]
    fn allow_adds_exceptions_but_open_needs_none() {
        let mut spec = NetSpec {
            allow: vec!["10.9.0.0/16".parse().unwrap()],
            ..NetSpec::default()
        };
        assert!(ruleset(&spec, &[]).contains("elements = { 10.9.0.0/16 }"));
        spec.egress = Egress::DenyAll;
        let r = ruleset(&spec, &[]);
        assert!(
            r.contains("elements = { 0.0.0.0/0 }") && r.contains("elements = { 10.9.0.0/16 }"),
            "{r}"
        );
        spec.egress = Egress::Open;
        let r = ruleset(&spec, &["192.168.5.15/32".parse().unwrap()]);
        assert!(!r.contains("elements"), "open has no deny or allow entries:\n{r}");
    }

    #[test]
    fn restricted_ipv6_denies_every_special_range_but_not_global_unicast() {
        let denied = |a: &str| {
            let a: IpAddr = a.parse().unwrap();
            RESTRICTED6.iter().any(|c| c.parse::<Cidr>().unwrap().contains(a))
        };
        for a in [
            "::",
            "::1",
            "::a00:1",            // IPv4-compatible
            "::ffff:10.0.0.1",    // IPv4-mapped
            "::ffff:0:a00:1",     // SIIT
            "64:ff9b::a9fe:a9fe", // NAT64 (169.254.169.254)
            "64:ff9b:1::1",       // local-use NAT64
            "100::1",             // discard-only
            "5f00::1",            // SRv6 SIDs
            "fd00:ec2::254",      // ULA (AWS metadata)
            "fc00::1",
            "fe80::1",
            "fec0::1", // site-local
            "ff02::1",
            "2001::1",       // Teredo
            "2001:2::1",     // benchmarking
            "2001:db8::1",   // documentation
            "3fff::1",       // documentation
            "2002:a00:1::1", // 6to4 (10.0.0.1)
        ] {
            assert!(denied(a), "{a} is not denied");
        }
        for a in [
            "2606:4700::1111",
            "2a00:1450:4001::1",
            "2001:4860:4860::8888",
            "3ffe::7",
        ] {
            assert!(!denied(a), "{a} is denied");
        }
    }

    #[test]
    fn ipv6_destinations_have_their_own_sets() {
        let r = ruleset(
            &NetSpec::default(),
            &["192.168.5.15/32".parse().unwrap(), "3ffe:0:0:1::/64".parse().unwrap()],
        );
        let set = |name: &str| {
            let at = r
                .find(&format!("set {name} {{"))
                .unwrap_or_else(|| panic!("no set {name}:\n{r}"));
            r[at..].lines().next().unwrap().to_string()
        };
        assert!(set("deny6").contains("type ipv6_addr;"), "{r}");
        for range in RESTRICTED6 {
            assert!(set("deny6").contains(range), "{range} missing:\n{r}");
        }
        assert!(
            set("deny6").contains("3ffe:0:0:1::/64") && !set("deny").contains("3ffe"),
            "{r}"
        );
        assert!(
            set("deny").contains("192.168.5.15/32") && !set("deny6").contains("192.168"),
            "{r}"
        );
        assert_eq!(
            set("allow6"),
            "set allow6 { type ipv6_addr; flags interval; auto-merge; }"
        );

        let allow = |egress, allow: &[&str]| {
            ruleset(
                &NetSpec {
                    egress,
                    allow: allow.iter().map(|a| a.parse().unwrap()).collect(),
                    ..NetSpec::default()
                },
                &[],
            )
        };
        let r = allow(Egress::Restricted, &["fd00:250::1", "10.9.0.0/16"]);
        assert!(
            r.contains("set allow6 { type ipv6_addr; flags interval; auto-merge; elements = { fd00:250::1/128 } }"),
            "{r}"
        );
        assert!(r.contains("set allow { type ipv4_addr; flags interval; auto-merge; elements = { 10.9.0.0/16 } }"));
        let r = allow(Egress::DenyAll, &["fd00:250::1"]);
        assert!(
            r.contains("elements = { ::/0 }") && r.contains("elements = { 0.0.0.0/0 }"),
            "{r}"
        );
        assert!(r.contains("elements = { fd00:250::1/128 }"), "{r}");
        let r = allow(Egress::Open, &["fd00:250::1"]);
        assert!(!r.contains("elements"), "open has no deny or allow entries:\n{r}");
    }

    #[test]
    fn ipv6_from_the_guest_is_policed_like_ipv4() {
        let r = ruleset(&NetSpec::default(), &[]);
        let at = |needle: &str| r.find(needle).unwrap_or_else(|| panic!("{needle} missing:\n{r}"));
        assert!(!r.contains("meta nfproto ipv6 drop"), "{r}");
        assert!(at("iifname \"tap0\" ip6 saddr != fd76:6d6b:6974::2 drop") < at("ct state established,related accept"));
        assert!(at("oifname \"egress0\" ip6 daddr @allow6 accept") < at("oifname \"egress0\" ip6 daddr @deny6 drop"));
        assert!(at("ip6 daddr @deny6 drop") < at("iifname \"tap0\" oifname \"egress0\" accept"));
        // A bare namespace still drops IPv6.
        assert!(egress_ruleset(&NetSpec::default(), &[]).contains("meta nfproto ipv6 drop"));
    }

    #[test]
    fn only_the_guests_neighbour_solicitations_reach_the_namespace() {
        let r = ruleset(&NetSpec::default(), &[]);
        let input = &r[r.find("chain input {").unwrap()..];
        let input = &input[..input.find("  }").unwrap()];
        assert_eq!(
            input.lines().map(str::trim).collect::<Vec<_>>(),
            [
                "chain input {",
                "type filter hook input priority filter; policy accept;",
                "iifname \"tap0\" ct state established,related accept",
                "iifname \"tap0\" ip6 saddr fd76:6d6b:6974::2 ip6 hoplimit 255 icmpv6 type nd-neighbor-solicit accept",
                "iifname \"tap0\" drop",
            ]
        );
    }

    #[test]
    fn spoofed_traffic_is_dropped_before_anything_is_accepted() {
        let r = ruleset(&NetSpec::default(), &[]);
        let at = |needle: &str| r.find(needle).unwrap_or_else(|| panic!("{needle} missing:\n{r}"));
        assert!(at("ip saddr != 172.30.0.2 drop") < at("ct state established,related accept"));
        assert!(at("ip daddr @allow accept") < at("ip daddr @deny drop"));
    }

    #[test]
    fn the_namespace_itself_opens_no_connection_through_pasta() {
        // The VMM runs in the namespace: its own connections take the output hook, not forward.
        for egress in [Egress::Restricted, Egress::DenyAll, Egress::Open] {
            let r = ruleset(
                &NetSpec {
                    egress,
                    ..NetSpec::default()
                },
                &[],
            );
            assert!(
                r.contains(
                    "  chain local_out {\n    type filter hook output priority filter; policy accept;\n    \
                     oifname \"egress0\" ct state new drop\n  }"
                ),
                "{egress:?}:\n{r}"
            );
        }
    }

    #[test]
    fn forwards_reach_the_guest_on_both_pasta_paths() {
        let spec = NetSpec {
            forwards: vec![
                PortForward {
                    protocol: Protocol::Tcp,
                    address: Ipv4Addr::LOCALHOST,
                    host: 8080,
                    guest: 80,
                },
                PortForward {
                    protocol: Protocol::Udp,
                    address: Ipv4Addr::UNSPECIFIED,
                    host: 5353,
                    guest: 53,
                },
                PortForward {
                    protocol: Protocol::Tcp,
                    address: Ipv4Addr::new(192, 168, 5, 15),
                    host: 8443,
                    guest: 443,
                },
            ],
            ..NetSpec::default()
        };
        let r = ruleset(&spec, &[]);
        assert!(
            r.contains("iifname != \"tap0\" fib daddr type local tcp dport 8080 dnat ip to 172.30.0.2:80"),
            "{r}"
        );
        assert!(
            r.contains("    fib daddr type local udp dport 5353 dnat ip to 172.30.0.2:53"),
            "{r}"
        );
        // The namespace side is the same whatever address pasta listens on.
        assert!(
            r.contains("iifname != \"tap0\" fib daddr type local tcp dport 8443 dnat ip to 172.30.0.2:443"),
            "{r}"
        );
        let args = pasta_args(&spec);
        let all =
            |flag: &str| -> Vec<String> { args.windows(2).filter(|w| w[0] == flag).map(|w| w[1].clone()).collect() };
        // One spec per forward, each bound to its own address.
        assert_eq!(all("--tcp-ports"), ["127.0.0.1/8080", "192.168.5.15/8443"]);
        assert_eq!(all("--udp-ports"), ["0.0.0.0/5353"]);
        assert_eq!(all("--tcp-ns"), ["none"]);
        let none = pasta_args(&NetSpec::default());
        let flags = |flag: &str| -> Vec<&String> { none.windows(2).filter(|w| w[0] == flag).map(|w| &w[1]).collect() };
        assert_eq!(flags("--tcp-ports"), ["none"]);
        assert_eq!(flags("--udp-ports"), ["none"]);
    }

    #[test]
    fn an_allow_entry_that_is_the_hosts_outbound_address_is_refused() {
        let copied = ["192.168.5.15".parse().unwrap(), "3ffe:0:0:1::1".parse().unwrap()];
        let spec = |egress, allow: &[&str]| NetSpec {
            egress,
            allow: allow.iter().map(|a| a.parse().unwrap()).collect(),
            ..NetSpec::default()
        };
        assert!(
            spec(Egress::Restricted, &["10.9.0.0/16", "1.1.1.1"])
                .check_allow(&copied)
                .is_ok()
        );
        let e = spec(Egress::DenyAll, &["10.9.0.0/16", "192.168.5.15"])
            .check_allow(&copied)
            .unwrap_err();
        assert!(
            e.contains("192.168.5.15/32 is the host's own address 192.168.5.15"),
            "{e}"
        );
        // A wider entry still reaches its other addresses; other host addresses (not
        // copied into the namespace) are reachable with an exception.
        assert!(
            spec(Egress::DenyAll, &["192.168.0.0/16", "10.250.0.1"])
                .check_allow(&copied)
                .is_ok()
        );
        // pasta copies the host's IPv6 address too.
        let e = spec(Egress::Restricted, &["3ffe:0:0:1::1"])
            .check_allow(&copied)
            .unwrap_err();
        assert!(
            e.contains("3ffe:0:0:1::1/128 is the host's own address 3ffe:0:0:1::1"),
            "{e}"
        );
        assert!(
            spec(Egress::Restricted, &["3ffe:0:0:1::/64"])
                .check_allow(&copied)
                .is_ok()
        );
        // `open` ignores `allow`.
        assert!(spec(Egress::Open, &["192.168.5.15"]).check_allow(&copied).is_ok());
        let c: Cidr = "192.168.4.0/23".parse().unwrap();
        assert!(c.contains("192.168.5.255".parse().unwrap()) && !c.contains("192.168.6.0".parse().unwrap()));
        assert!(
            "0.0.0.0/0"
                .parse::<Cidr>()
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
    }

    #[test]
    fn duplicate_or_zero_ports_are_refused() {
        let fwd = |host, guest| PortForward {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::LOCALHOST,
            host,
            guest,
        };
        let spec = |forwards| NetSpec {
            forwards,
            ..NetSpec::default()
        };
        assert!(spec(vec![fwd(80, 80), fwd(81, 80)]).check().is_ok());
        assert!(spec(vec![fwd(80, 80), fwd(80, 81)]).check().is_err());
        assert!(spec(vec![fwd(0, 80)]).check().is_err());
        let mut udp = fwd(80, 80);
        udp.protocol = Protocol::Udp;
        assert!(
            spec(vec![fwd(80, 80), udp]).check().is_ok(),
            "tcp and udp ports are separate"
        );
        // The namespace sees only the port, so two addresses cannot share it.
        let mut other = fwd(80, 81);
        other.address = Ipv4Addr::UNSPECIFIED;
        assert!(spec(vec![fwd(80, 80), other]).check().is_err());
    }

    #[test]
    fn host_addresses_come_from_the_local_routes() {
        let trie = "Main:\n  +-- 0.0.0.0/0 3 0 4\n     |-- 0.0.0.0\n        /0 universe UNICAST\n     \
                    +-- 127.0.0.0/8 2 0 2\n        |-- 127.0.0.1\n           /32 host LOCAL\n        \
                    |-- 127.255.255.255\n           /32 link BROADCAST\n     |-- 192.168.5.15\n           \
                    /32 host LOCAL\nLocal:\n     |-- 192.168.5.15\n           /32 host LOCAL\n";
        assert_eq!(
            host_addresses(trie),
            [
                "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                "192.168.5.15".parse().unwrap()
            ]
        );
    }
}
