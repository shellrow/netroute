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
    pub address: IpAddr,
    /// Prefix length in bits.
    pub prefix_length: u8,
}

impl RouteDestination {
    /// Creates a new [`RouteDestination`].
    pub fn new(address: IpAddr, prefix_length: u8) -> Self {
        Self {
            address,
            prefix_length,
        }
    }
}

impl fmt::Display for RouteDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_length)
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
