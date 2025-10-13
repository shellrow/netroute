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
    /// Creates a new [`RouteDestination`].
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        Self {
            addr,
            prefix_len,
        }
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
    /// Returns a single-character abbreviation commonly used by `netstat` or `ip route`.
    ///
    /// Examples:
    /// - `Up` → `"U"`
    /// - `Gateway` → `"G"`
    /// - `Host` → `"H"`
    /// - `Link` → `"L"`
    /// - `Reject` → `"R"`
    /// - `Static` → `"S"`
    /// - `Loopback` → `"L"`
    /// - `Other(x)` → first char of `x` (uppercased)
    pub fn short(&self) -> String {
        match self {
            RouteFlag::Up => "U".to_string(),
            RouteFlag::Gateway => "G".to_string(),
            RouteFlag::Host => "H".to_string(),
            RouteFlag::Link => "L".to_string(),
            RouteFlag::Reject => "R".to_string(),
            RouteFlag::Static => "S".to_string(),
            RouteFlag::Loopback => "L".to_string(),
            RouteFlag::Other(s) => s.chars().next().map(|c| c.to_ascii_uppercase().to_string()).unwrap_or("?".to_string()),
        }
    }

    /// Returns a human-readable description of this flag.
    ///
    /// Examples:
    /// - `"U"` → `"Up (route is usable)"`
    /// - `"G"` → `"Gateway (next-hop via router)"`
    /// - `"H"` → `"Host (single-host route)"`
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

    /// Converts a single-character abbreviation (like `"U"`, `"G"`) back into a [`RouteFlag`].
    pub fn from_short(ch: &str) -> Option<Self> {
        match ch.to_ascii_uppercase().as_str() {
            "U" => Some(RouteFlag::Up),
            "G" => Some(RouteFlag::Gateway),
            "H" => Some(RouteFlag::Host),
            "L" => Some(RouteFlag::Link),
            "R" => Some(RouteFlag::Reject),
            "S" => Some(RouteFlag::Static),
            _ => Some(RouteFlag::Other(ch.to_string())),
        }
    }
}

/// Known routing protocols that may appear in the table.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RouteProtocol {
    Unspecified,
    IcmpRedirect,
    Kernel,
    Boot,
    Static,
    Gated,
    RouterAdvertisement,
    Mrt,
    Mrouted,
    Zebra,
    Bird,
    DnRouted,
    Xorp,
    Ntk,
    Dhcp,
    KeepAlived,
    Babel,
    Bgp,
    Isis,
    Ospf,
    Rip,
    Eigrp,
    Local,
    NetMgmt,
    Icmp,
    Egp,
    Ggp,
    Hello,
    Esis,
    Cisco,
    Bbn,
    Autostatic,
    StaticNonDod,
    Rpl,
    Other(String),
}

/// Scope of the route.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RouteScope {
    Global,
    Site,
    Link,
    Host,
    Nowhere,
    Other(String),
}

/// A single entry from the operating system routing table.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RouteEntry {
    /// IP protocol family (IPv4 or IPv6).
    pub family: RouteFamily,
    /// Destination network.
    pub destination: RouteDestination,
    /// Gateway IP address if the route is not on-link.
    pub gateway: Option<IpAddr>,
    /// Whether the next hop resides on the local link.
    pub on_link: bool,
    /// Interface index associated with the route.
    pub ifindex: Option<u32>,
    /// Human readable interface name, when available.
    pub ifname: Option<String>,
    /// Routing metric provided by the OS.
    pub metric: Option<u32>,
    /// Flags describing additional route characteristics.
    pub flags: Vec<RouteFlag>,
    /// Routing protocol that installed the route.
    pub protocol: Option<RouteProtocol>,
    /// Visibility scope of the route.
    pub scope: Option<RouteScope>,
    /// Routing table identifier (platform specific).
    pub table: Option<u32>,
    /// Remaining lifetime of the route in milliseconds, if available.
    pub lifetime_ms: Option<u64>,
}

/// Returns the list of routing table entries reported by the underlying operating system.
pub fn list_routes() -> std::io::Result<Vec<RouteEntry>> {
    os::list_routes()
}
