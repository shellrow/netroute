//! Read IPv4 and IPv6 routing tables through native operating system APIs.
//!
//! ```no_run
//! for route in netroute::list_routes()? {
//!     println!("{} via {:?}", route.destination, route.gateway);
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

mod os;

use std::fmt;
use std::net::IpAddr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// IP version of a routing table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RouteFamily {
    /// IPv4 route.
    Ipv4,
    /// IPv6 route.
    Ipv6,
}

impl From<IpAddr> for RouteFamily {
    fn from(addr: IpAddr) -> Self {
        if addr.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }
}

impl fmt::Display for RouteFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteFamily::Ipv4 => f.write_str("IPv4"),
            RouteFamily::Ipv6 => f.write_str("IPv6"),
        }
    }
}

/// Destination network of a route expressed as an address and prefix length.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RouteDestination {
    /// Network address.
    pub addr: IpAddr,
    /// Prefix length in bits.
    pub prefix_len: u8,
}

impl RouteDestination {
    /// Stores the supplied address and prefix length without validation or masking.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
    }
}

impl fmt::Display for RouteDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// Well-known routing flags.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RouteFlag {
    /// Route is active.
    Up,
    /// Route uses a gateway.
    Gateway,
    /// Route targets a single host.
    Host,
    /// Route is restricted to the local link.
    Link,
    /// Route rejects matching traffic.
    Reject,
    /// Route was statically installed.
    Static,
    /// Route targets the loopback interface.
    Loopback,
    /// Platform-specific flag that is not covered by the predefined variants.
    Other(String),
}

impl RouteFlag {
    /// Returns the single-character abbreviation as a code point.
    pub fn short_code(&self) -> char {
        match self {
            RouteFlag::Up => 'U',
            RouteFlag::Gateway => 'G',
            RouteFlag::Host => 'H',
            RouteFlag::Link => 'L',
            RouteFlag::Reject => 'R',
            RouteFlag::Static => 'S',
            RouteFlag::Loopback => 'L',
            RouteFlag::Other(s) => s
                .chars()
                .next()
                .map(|c| c.to_ascii_uppercase())
                .unwrap_or('?'),
        }
    }

    /// Formats [`Self::short_code`] as a string.
    pub fn short(&self) -> String {
        self.short_code().to_string()
    }

    /// Returns a human-readable description of this flag.
    pub fn description(&self) -> &'static str {
        match self {
            RouteFlag::Up => "Up (route is usable)",
            RouteFlag::Gateway => "Gateway (next-hop via router)",
            RouteFlag::Host => "Host (single-host route)",
            RouteFlag::Link => "Link (restricted to local link)",
            RouteFlag::Reject => "Reject (deny matching traffic)",
            RouteFlag::Static => "Static (manually installed)",
            RouteFlag::Loopback => "Loopback (local loopback route)",
            RouteFlag::Other(_) => "Other (platform-specific)",
        }
    }

    /// Parses one abbreviation, ignoring ASCII case. The historical `L` code
    /// is shared by link and loopback flags and parses as [`Self::Link`].
    pub fn from_short(ch: &str) -> Option<Self> {
        let mut chars = ch.chars();
        let c = chars.next()?;
        if chars.next().is_some() {
            return None;
        }

        match c.to_ascii_uppercase() {
            'U' => Some(RouteFlag::Up),
            'G' => Some(RouteFlag::Gateway),
            'H' => Some(RouteFlag::Host),
            'L' => Some(RouteFlag::Link),
            'R' => Some(RouteFlag::Reject),
            'S' => Some(RouteFlag::Static),
            _ => Some(RouteFlag::Other(ch.to_ascii_uppercase())),
        }
    }
}

/// Known routing protocols that may appear in the table.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RouteProtocol {
    /// No protocol was specified.
    Unspecified,
    /// Installed by an ICMP redirect.
    IcmpRedirect,
    /// Installed by the kernel.
    Kernel,
    /// Installed during boot.
    Boot,
    /// Static route.
    Static,
    /// GateD routing daemon.
    Gated,
    /// IPv6 router advertisement.
    RouterAdvertisement,
    /// MRT routing daemon.
    Mrt,
    /// Multicast routing daemon (mrouted).
    Mrouted,
    /// Zebra routing daemon.
    Zebra,
    /// BIRD routing daemon.
    Bird,
    /// DECnet routing daemon.
    DnRouted,
    /// XORP routing software.
    Xorp,
    /// Netsukuku routing protocol.
    Ntk,
    /// Dynamic Host Configuration Protocol.
    Dhcp,
    /// Keepalived routing software.
    KeepAlived,
    /// Babel routing protocol.
    Babel,
    /// Border Gateway Protocol.
    Bgp,
    /// Intermediate System to Intermediate System.
    Isis,
    /// Open Shortest Path First.
    Ospf,
    /// Routing Information Protocol.
    Rip,
    /// Enhanced Interior Gateway Routing Protocol.
    Eigrp,
    /// Windows local route.
    Local,
    /// Installed through Windows network management.
    NetMgmt,
    /// Internet Control Message Protocol.
    Icmp,
    /// Exterior Gateway Protocol.
    Egp,
    /// Gateway-to-Gateway Protocol.
    Ggp,
    /// HELLO routing protocol.
    Hello,
    /// End System to Intermediate System.
    Esis,
    /// Cisco routing protocol reported by Windows.
    Cisco,
    /// BBN routing protocol reported by Windows.
    Bbn,
    /// Windows demand-dial autostatic route.
    Autostatic,
    /// Windows static route that does not initiate demand dialing.
    StaticNonDod,
    /// Routing Protocol for Low-Power and Lossy Networks.
    Rpl,
    /// Platform-specific protocol name or numeric identifier.
    Other(String),
}

/// Scope of the route.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RouteScope {
    /// Reachable beyond the local site.
    Global,
    /// Reachable within the local site.
    Site,
    /// Reachable on the local link.
    Link,
    /// Local to this host.
    Host,
    /// Unreachable.
    Nowhere,
    /// Platform-specific scope identifier.
    Other(String),
}

/// A single entry from the operating system routing table.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RouteEntry {
    /// IP protocol family (IPv4 or IPv6).
    pub family: RouteFamily,
    /// Destination network.
    pub destination: RouteDestination,
    /// IP next hop, when reported.
    pub gateway: Option<IpAddr>,
    /// Whether the route delivers directly without an intermediate gateway.
    /// Discard routes and unresolved nexthops are not on-link.
    pub on_link: bool,
    /// Interface index associated with the route.
    pub ifindex: Option<u32>,
    /// Interface name (Windows interface alias), when available.
    pub ifname: Option<String>,
    /// Route priority on Linux and OpenBSD, or the route metric offset on Windows.
    /// Windows adds the interface metric when choosing a route.
    pub metric: Option<u32>,
    /// Flags describing additional route characteristics.
    pub flags: Vec<RouteFlag>,
    /// Routing protocol that installed the route.
    pub protocol: Option<RouteProtocol>,
    /// Kernel-reported route scope on Linux and Android.
    pub scope: Option<RouteScope>,
    /// Routing table identifier (platform specific).
    pub table: Option<u32>,
    /// Finite route lifetime reported by the OS, in milliseconds.
    /// `None` means infinite or unavailable.
    pub lifetime_ms: Option<u64>,
    /// Explicit IPv6 zone reported for the destination, if present.
    pub destination_scope_id: Option<u32>,
    /// Explicit IPv6 zone reported for the gateway, if present. For link-local
    /// gateways without an explicit zone, use the outgoing interface index.
    pub gateway_scope_id: Option<u32>,
    /// Source prefix required for a match on a source-specific Linux route.
    pub source: Option<RouteDestination>,
    /// Linux nexthop object ID, when the route references one.
    pub next_hop_id: Option<u32>,
    /// Relative weight of this next hop in an inline Linux multipath route.
    pub next_hop_weight: Option<u16>,
}

/// Reads IPv4 and IPv6 routes visible to the calling process.
///
/// An inline Linux multipath route yields one entry per next hop. An empty
/// routing table yields an empty vector. Ordering is platform-dependent.
/// Apple platforms and OpenBSD omit cloned cache entries. BSD routes with
/// non-contiguous masks are omitted because they have no CIDR prefix length.
///
/// # Errors
///
/// Returns an I/O error if the OS denies access or the routing dump fails.
/// Unsupported targets return [`std::io::ErrorKind::Unsupported`].
pub fn list_routes() -> std::io::Result<Vec<RouteEntry>> {
    os::list_routes()
}
