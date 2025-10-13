use crate::{
    RouteDestination, RouteEntry, RouteFamily, RouteFlag, RouteProtocol as RouteProtocolKind,
    RouteScope as RouteScopeKind,
};

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{
    collections::HashMap,
    io, thread,
    time::{Duration, Instant},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteScope, RouteProtocol};

const SEQ_BASE: u32 = 0x6e_72_74_65; // "nrte"
const RECV_BUFSZ: usize = 1 << 20; // 1MB
const RECV_TIMEOUT: Duration = Duration::from_secs(2);
const NLMSG_ALIGNTO: usize = 4;
const MIN_NLMSG_HEADER_LEN: usize = 16;

#[inline]
fn nlmsg_align(n: usize) -> usize {
    (n + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

#[cfg(target_os = "linux")]
fn open_route_socket() -> io::Result<Socket> {
    let mut sock = Socket::new(NETLINK_ROUTE)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("netlink open: {e}")))?;
    sock.bind_auto()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("bind_auto: {e}")))?;
    sock.set_non_blocking(true).ok();
    Ok(sock)
}

#[cfg(target_os = "android")]
fn open_route_socket() -> io::Result<Socket> {
    let sock = Socket::new(NETLINK_ROUTE)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("netlink open: {e}")))?;
    // On Android 11+, bind is denied by SELinux
    //sock.bind_auto().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("bind_auto: {e}")))?;
    sock.set_non_blocking(true).ok();
    Ok(sock)
}

fn send_dump(sock: &mut Socket, msg: RouteNetlinkMessage, seq: u32) -> io::Result<()> {
    let mut nl = NetlinkMessage::from(msg);
    nl.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl.header.sequence_number = seq;
    nl.header.port_number = 0;

    // Finalize to set length
    nl.finalize();

    let blen = nl.buffer_len();
    if blen < MIN_NLMSG_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("netlink message too short: buffer_len={}", blen),
        ));
    }

    let mut buf = vec![0; blen];
    nl.serialize(&mut buf);

    let kernel = SocketAddr::new(0, 0);
    sock.send_to(&buf, &kernel, 0)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("netlink send: {e}")))?;
    Ok(())
}

fn recv_multi(
    sock: &mut Socket,
    expect_seq: u32,
) -> io::Result<Vec<NetlinkMessage<RouteNetlinkMessage>>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; RECV_BUFSZ];
    let kernel = SocketAddr::new(0, 0);
    let deadline = Instant::now() + RECV_TIMEOUT;

    loop {
        match sock.recv_from(&mut &mut buf[..], 0) {
            Ok((size, from)) => {
                let _ = from == kernel;
                let mut offset = 0usize;

                while offset < size {
                    if size - offset < MIN_NLMSG_HEADER_LEN {
                        break;
                    }

                    let bytes = &buf[offset..size];

                    let msg =
                        NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes).map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("deserialize: {e:?}"),
                            )
                        })?;

                    let consumed = msg.header.length as usize;
                    if consumed < MIN_NLMSG_HEADER_LEN || offset + consumed > size {
                        break;
                    }

                    if msg.header.sequence_number != expect_seq {
                        offset += nlmsg_align(consumed);
                        continue;
                    }

                    match &msg.payload {
                        NetlinkPayload::Done(_) => {
                            return Ok(out);
                        }
                        NetlinkPayload::Error(e) => {
                            if let Some(code) = e.code {
                                return Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("netlink error: code={}", code),
                                ));
                            }
                            // code==None: possibly ACK ... ignore
                        }
                        NetlinkPayload::Noop | NetlinkPayload::Overrun(_) => { /* skip */ }
                        _ => out.push(msg),
                    }

                    // Align to 4-byte boundary
                    offset += nlmsg_align(consumed);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    // timeout
                    return Ok(out);
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    }
}

pub fn dump_routes() -> io::Result<Vec<RouteMessage>> {
    let mut sock = open_route_socket()?;
    let seq = SEQ_BASE ^ 0x03;
    send_dump(
        &mut sock,
        RouteNetlinkMessage::GetRoute(RouteMessage::default()),
        seq,
    )?;
    let msgs = recv_multi(&mut sock, seq)?;
    let mut out = Vec::new();
    for m in msgs {
        if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt)) = m.payload {
            out.push(rt);
        }
    }
    Ok(out)
}

fn route_addr_to_ip(a: &RouteAddress) -> Option<IpAddr> {
    match a {
        RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        _ => None,
    }
}

fn route_extract(rt: &RouteMessage) -> (Option<IpAddr>, Option<u8>, Option<IpAddr>, Option<u32>) {
    // (dst, prefix, gateway, oif)
    let mut dst: Option<IpAddr> = None;
    let pfx: Option<u8> = Some(rt.header.destination_prefix_length);
    let mut gw: Option<IpAddr> = None;
    let mut oif: Option<u32> = None;

    for nla in &rt.attributes {
        match nla {
            RouteAttribute::Destination(a) => dst = route_addr_to_ip(a),
            RouteAttribute::Gateway(a) => gw = route_addr_to_ip(a),
            RouteAttribute::Oif(i) => oif = Some(*i),
            _ => {}
        }
    }

    // if dst is None and pfx is 0, it means default route
    if dst.is_none() && pfx == Some(0) {
        dst = match rt.header.address_family {
            AddressFamily::Inet => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            AddressFamily::Inet6 => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            _ => None,
        };
    }

    (dst, pfx, gw, oif)
}

fn linux_proto_to_route_protocol(p: RouteProtocol) -> Option<RouteProtocolKind> {
    let proto = match p {
        RouteProtocol::Unspec => RouteProtocolKind::Unspecified,
        RouteProtocol::IcmpRedirect => RouteProtocolKind::IcmpRedirect,
        RouteProtocol::Kernel => RouteProtocolKind::Kernel,
        RouteProtocol::Boot => RouteProtocolKind::Boot,
        RouteProtocol::Static => RouteProtocolKind::Static,
        RouteProtocol::Gated => RouteProtocolKind::Gated,
        RouteProtocol::Ra => RouteProtocolKind::RouterAdvertisement,
        RouteProtocol::Mrt => RouteProtocolKind::Mrt,
        RouteProtocol::Zebra => RouteProtocolKind::Zebra,
        RouteProtocol::Bird => RouteProtocolKind::Bird,
        RouteProtocol::DnRouted => RouteProtocolKind::DnRouted,
        RouteProtocol::Xorp => RouteProtocolKind::Xorp,
        RouteProtocol::Ntk => RouteProtocolKind::Ntk,
        RouteProtocol::Dhcp => RouteProtocolKind::Dhcp,
        RouteProtocol::Mrouted => RouteProtocolKind::Mrouted,
        RouteProtocol::KeepAlived => RouteProtocolKind::KeepAlived,
        RouteProtocol::Babel => RouteProtocolKind::Babel,
        RouteProtocol::Bgp => RouteProtocolKind::Bgp,
        RouteProtocol::Isis => RouteProtocolKind::Isis,
        RouteProtocol::Ospf => RouteProtocolKind::Ospf,
        RouteProtocol::Rip => RouteProtocolKind::Rip,
        RouteProtocol::Eigrp => RouteProtocolKind::Eigrp,
        RouteProtocol::Other(s) => RouteProtocolKind::Other(s.to_string()),
        #[allow(unreachable_patterns)]
        _ => return None,
    };
    Some(proto)
}

fn linux_scope_to_route_scope(scope: RouteScope) -> Option<RouteScopeKind> {
    let scope = match scope {
        RouteScope::Universe => RouteScopeKind::Global,
        RouteScope::Site => RouteScopeKind::Site,
        RouteScope::Link => RouteScopeKind::Link,
        RouteScope::Host => RouteScopeKind::Host,
        RouteScope::NoWhere => RouteScopeKind::Nowhere,
        RouteScope::Other(s) => RouteScopeKind::Other(s.to_string()),
        #[allow(unreachable_patterns)]
        _ => return None,
    };
    Some(scope)
}

fn route_metric(attrs: &[RouteAttribute]) -> Option<u32> {
    for a in attrs {
        if let RouteAttribute::Priority(m) = a {
            return Some(*m);
        }
    }
    None
}

fn flags_from_linux(
    rt: &RouteMessage,
    on_link: bool,
    prefix_len: Option<u8>,
    dst: &Option<IpAddr>,
) -> Vec<RouteFlag> {
    // - "U": up
    // - "G": gateway (next-hop, not on_link)
    // - "H": host route (32 or 128)
    // - "L": link/scope==link
    let mut v = vec![RouteFlag::Up];
    if !on_link {
        v.push(RouteFlag::Gateway);
    }
    if let (Some(pfx), Some(ip)) = (prefix_len, dst) {
        let is_host = match (ip, pfx) {
            (IpAddr::V4(_), 32) => true,
            (IpAddr::V6(_), 128) => true,
            _ => false,
        };
        if is_host {
            v.push(RouteFlag::Host);
        }
    }
    if matches!(
        linux_scope_to_route_scope(rt.header.scope),
        Some(RouteScopeKind::Link)
    ) {
        v.push(RouteFlag::Link);
    }
    v
}

fn family_from_af(af: AddressFamily) -> Option<RouteFamily> {
    match af {
        AddressFamily::Inet => Some(RouteFamily::Ipv4),
        AddressFamily::Inet6 => Some(RouteFamily::Ipv6),
        _ => None,
    }
}

pub fn list_routes_linux() -> io::Result<Vec<RouteEntry>> {
    let if_map: HashMap<u32, String> = crate::os::unix::unix_interface_map();

    let rts = dump_routes()?;

    let mut out = Vec::new();

    for rt in rts {
        let family = match family_from_af(rt.header.address_family) {
            Some(f) => f,
            None => continue,
        };

        let (dst_ip_opt, pfx_opt, gw_ip_opt, oif_opt) = route_extract(&rt);

        // default route
        let (dst_ip, pfx) = match (dst_ip_opt, pfx_opt) {
            (Some(ip), Some(p)) => (ip, p),
            (None, Some(0)) => match family {
                RouteFamily::Ipv4 => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                RouteFamily::Ipv6 => (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            },
            (Some(IpAddr::V4(ip)), None) => (IpAddr::V4(ip), 32),
            (Some(IpAddr::V6(ip)), None) => (IpAddr::V6(ip), 128),
            _ => continue,
        };

        let destination = RouteDestination::new(dst_ip, pfx);

        let on_link = gw_ip_opt.is_none();
        let gateway = if on_link { None } else { gw_ip_opt };

        // ifindex / ifname
        let ifindex = oif_opt;
        let ifname = ifindex.and_then(|i| if_map.get(&i).cloned());

        // metric
        let metric = route_metric(&rt.attributes);

        // proto / scope / table
        let protocol = linux_proto_to_route_protocol(rt.header.protocol);
        let scope = linux_scope_to_route_scope(rt.header.scope);
        let table = Some(rt.header.table as u32);

        // flags (U, G, H, L, ...)
        let flags = flags_from_linux(&rt, on_link, Some(pfx), &Some(dst_ip));

        let lifetime_ms = None;

        out.push(RouteEntry {
            family,
            destination,
            gateway,
            on_link,
            ifindex,
            ifname,
            metric,
            flags,
            protocol,
            scope,
            table,
            lifetime_ms,
        });
    }

    Ok(out)
}
