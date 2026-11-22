use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
};

use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkBuffer, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteNextHop, RouteNextHopFlags,
        RouteProtocol, RouteScope, RouteType, RouteVia,
    },
};
use nix::sys::{
    socket::{self, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, sockopt},
    time::TimeVal,
};

use super::unix::InterfaceNames;
use crate::{
    RouteDestination, RouteEntry, RouteFamily, RouteFlag, RouteProtocol as RouteProtocolKind,
    RouteScope as RouteScopeKind,
};

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn kernel_error(code: i32) -> io::Error {
    match code.checked_neg() {
        Some(errno) if errno > 0 => io::Error::from_raw_os_error(errno),
        _ => invalid("invalid netlink error code"),
    }
}

fn parse_datagram(
    mut bytes: &[u8],
    seq: u32,
    mut route: impl FnMut(RouteMessage) -> io::Result<()>,
) -> io::Result<bool> {
    if bytes.is_empty() {
        return Err(invalid("empty netlink datagram"));
    }
    while !bytes.is_empty() {
        let packet = NetlinkBuffer::new_checked(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let len = packet.length() as usize;
        let frame = &bytes[..len];
        // The final frame does not require trailing padding.
        bytes = if len == bytes.len() {
            &[]
        } else {
            bytes
                .get(len.next_multiple_of(4)..)
                .ok_or_else(|| invalid("short netlink padding"))?
        };
        if packet.sequence_number() != seq {
            continue;
        }
        if packet.flags() & NLM_F_DUMP_INTR != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "routing table changed during dump",
            ));
        }
        let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        match msg.payload {
            NetlinkPayload::Done(done) if done.code == 0 => return Ok(true),
            NetlinkPayload::Done(done) => return Err(kernel_error(done.code)),
            NetlinkPayload::Error(err) => {
                if let Some(code) = err.code {
                    return Err(kernel_error(code.get()));
                }
            }
            NetlinkPayload::Overrun(_) => return Err(io::Error::from_raw_os_error(libc::ENOBUFS)),
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt)) => route(rt)?,
            _ => {}
        }
    }
    Ok(false)
}

fn dump() -> io::Result<Vec<RouteEntry>> {
    // send_to autobinds a private port, including on Android where an explicit
    // bind may be denied. Each dump owns its socket and sequence space.
    let sock = socket::socket(
        socket::AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )?;
    socket::setsockopt(&sock, sockopt::ReceiveTimeout, &TimeVal::new(2, 0))?;
    let fd = sock.as_raw_fd();
    let kernel = NetlinkAddr::new(0, 0);
    let mut request = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(RouteMessage::default()));
    request.header.sequence_number = 1;
    request.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.finalize();
    let mut bytes = vec![0; request.buffer_len()];
    request.serialize(&mut bytes);
    socket::sendto(fd, &bytes, &kernel, MsgFlags::empty())?;

    let mut names = InterfaceNames::default();
    let mut out = Vec::new();
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    loop {
        // Peek at the datagram size so a large route cannot be truncated.
        // This private socket has a single reader.
        let len =
            socket::recv(fd, &mut [], MsgFlags::MSG_PEEK | MsgFlags::MSG_TRUNC).map_err(|e| {
                if e == nix::errno::Errno::EAGAIN {
                    io::ErrorKind::TimedOut.into()
                } else {
                    io::Error::from(e)
                }
            })?;
        bytes.resize(len, 0);
        let (read, from) = socket::recvfrom::<NetlinkAddr>(fd, &mut bytes)?;
        if read != len {
            return Err(invalid("incomplete netlink datagram"));
        }
        if from == Some(kernel)
            && parse_datagram(&bytes, request.header.sequence_number, |rt| {
                append_route(rt, &mut names, ticks, &mut out)
            })?
        {
            return Ok(out);
        }
    }
}

pub(crate) fn list_routes() -> io::Result<Vec<RouteEntry>> {
    for attempt in 0..3 {
        match dump() {
            Err(e)
                if attempt < 2
                    && (e.kind() == io::ErrorKind::Interrupted
                        || e.raw_os_error() == Some(libc::ENOBUFS)) =>
            {
                continue;
            }
            result => return result,
        }
    }
    unreachable!()
}

fn linux_proto_to_route_protocol(p: RouteProtocol) -> RouteProtocolKind {
    match p {
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
        other => RouteProtocolKind::Other(u8::from(other).to_string()),
    }
}

fn linux_scope_to_route_scope(scope: RouteScope) -> RouteScopeKind {
    match scope {
        RouteScope::Universe => RouteScopeKind::Global,
        RouteScope::Site => RouteScopeKind::Site,
        RouteScope::Link => RouteScopeKind::Link,
        RouteScope::Host => RouteScopeKind::Host,
        RouteScope::NoWhere => RouteScopeKind::Nowhere,
        other => RouteScopeKind::Other(u8::from(other).to_string()),
    }
}

fn address(addr: &RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(ip) => Some((*ip).into()),
        RouteAddress::Inet6(ip) => Some((*ip).into()),
        _ => None,
    }
}

fn gateway(attrs: &[RouteAttribute]) -> Option<IpAddr> {
    attrs.iter().find_map(|a| match a {
        RouteAttribute::Gateway(addr) => address(addr),
        RouteAttribute::Via(RouteVia::Inet(ip)) => Some((*ip).into()),
        RouteAttribute::Via(RouteVia::Inet6(ip)) => Some((*ip).into()),
        _ => None,
    })
}

fn append_route(
    rt: RouteMessage,
    names: &mut InterfaceNames,
    ticks: libc::c_long,
    out: &mut Vec<RouteEntry>,
) -> io::Result<()> {
    let hdr = rt.header;
    let (zero, width): (IpAddr, u8) = match hdr.address_family {
        AddressFamily::Inet => (Ipv4Addr::UNSPECIFIED.into(), 32),
        AddressFamily::Inet6 => (Ipv6Addr::UNSPECIFIED.into(), 128),
        _ => return Ok(()),
    };
    let prefix = hdr.destination_prefix_length;
    if prefix > width || hdr.source_prefix_length > width {
        return Err(invalid("invalid IP route prefix length"));
    }
    let mut dst = (prefix == 0).then_some(zero);
    let mut src = None;
    let mut table = u32::from(hdr.table);
    let mut metric = None;
    let mut ifindex = None;
    let mut multipath = None;
    let mut next_hop_id = None;
    let mut lifetime_ms = None;
    for attr in &rt.attributes {
        match attr {
            RouteAttribute::Destination(addr) => dst = address(addr),
            RouteAttribute::Source(addr) => src = address(addr),
            RouteAttribute::Table(id) => table = *id,
            RouteAttribute::Priority(n) => metric = Some(*n),
            RouteAttribute::Oif(i) => ifindex = Some(*i),
            RouteAttribute::MultiPath(hops) => multipath = Some(hops),
            RouteAttribute::NhId(id) => next_hop_id = Some(*id),
            RouteAttribute::CacheInfo(cache) if cache.expires != 0 && ticks > 0 => {
                // Linux exports rta_expires as signed clock ticks.
                lifetime_ms = Some((cache.expires as i32).max(0) as u64 * 1000 / ticks as u64);
            }
            _ => {}
        }
    }
    let dst = dst.ok_or_else(|| invalid("missing route destination"))?;
    if hdr.source_prefix_length != 0 && src.is_none() {
        return Err(invalid("missing route source"));
    }
    let source = src.map(|ip| RouteDestination::new(ip, hdr.source_prefix_length));
    let reject = matches!(
        hdr.kind,
        RouteType::BlackHole | RouteType::Unreachable | RouteType::Prohibit
    );
    let mut push = |hop: Option<&RouteNextHop>| {
        let (gateway, index) = match hop {
            Some(h) => (gateway(&h.attributes), Some(h.interface_index)),
            None => (gateway(&rt.attributes), ifindex),
        };
        let index = index.filter(|i| *i != 0);
        let unresolved = hdr.flags.contains(RouteFlags::Unresolved)
            || hop.is_some_and(|h| h.flags.contains(RouteNextHopFlags::Unresolved));
        let down = unresolved
            || hdr
                .flags
                .intersects(RouteFlags::Dead | RouteFlags::Linkdown)
            || hop.is_some_and(|h| {
                h.flags
                    .intersects(RouteNextHopFlags::Dead | RouteNextHopFlags::Linkdown)
            });
        let mut flags = Vec::new();
        if !down {
            flags.push(RouteFlag::Up);
        }
        if gateway.is_some() {
            flags.push(RouteFlag::Gateway);
        }
        if prefix == width {
            flags.push(RouteFlag::Host);
        }
        if hdr.scope == RouteScope::Link {
            flags.push(RouteFlag::Link);
        }
        if reject {
            flags.push(RouteFlag::Reject);
        }
        if hdr.protocol == RouteProtocol::Static {
            flags.push(RouteFlag::Static);
        }
        out.push(RouteEntry {
            family: RouteFamily::from(dst),
            destination: RouteDestination::new(dst, prefix),
            source: source.clone(),
            destination_scope_id: None,
            gateway_scope_id: None,
            next_hop_id,
            next_hop_weight: hop.map(|h| u16::from(h.hops) + 1),
            gateway,
            on_link: index.is_some()
                && gateway.is_none()
                && !unresolved
                && !reject
                && hdr.kind != RouteType::Throw,
            ifindex: index,
            ifname: index.and_then(|i| names.lookup(i)),
            metric,
            flags,
            protocol: Some(linux_proto_to_route_protocol(hdr.protocol)),
            scope: Some(linux_scope_to_route_scope(hdr.scope)),
            table: Some(table),
            lifetime_ms,
        });
    };
    match multipath {
        Some(hops) if hops.is_empty() => return Err(invalid("empty multipath route")),
        Some(hops) => {
            for hop in hops {
                push(Some(hop));
            }
        }
        None => push(None),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{NLMSG_DONE, NLMSG_OVERRUN};

    fn control(kind: u16, flags: u16, code: i32) -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes[..4].copy_from_slice(&20u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes[6..8].copy_from_slice(&flags.to_ne_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_ne_bytes());
        bytes[16..].copy_from_slice(&code.to_ne_bytes());
        bytes
    }

    #[test]
    fn only_a_successful_matching_done_completes_a_dump() {
        let parse = |data: &[u8], seq| parse_datagram(data, seq, |_| unreachable!());
        let done = control(NLMSG_DONE, 0, 0);
        assert!(!parse(&done, 2).unwrap());
        assert!(parse(&done, 1).unwrap());
        assert!(parse(&done[..18], 1).is_err());
        assert_eq!(
            parse(&control(NLMSG_DONE, 0, -libc::EPERM), 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            parse(&control(NLMSG_DONE, NLM_F_DUMP_INTR, 0), 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(
            parse(&control(NLMSG_OVERRUN, 0, 0), 1)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOBUFS)
        );
    }

    #[test]
    fn multipath_preserves_weights_interfaces_and_extended_table() {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        let mut first = RouteNextHop::default();
        first.interface_index = 7;
        first
            .attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet(
                [192, 0, 2, 1].into(),
            )));
        let mut second = RouteNextHop::default();
        second.interface_index = 8;
        second.hops = 255;
        second.flags = RouteNextHopFlags::Dead;
        second.attributes.push(RouteAttribute::Via(RouteVia::Inet6(
            "fe80::1".parse().unwrap(),
        )));
        msg.attributes = vec![
            RouteAttribute::Table(10001),
            RouteAttribute::MultiPath(vec![first, second]),
        ];
        let mut rows = Vec::new();
        append_route(msg, &mut InterfaceNames::default(), 100, &mut rows).unwrap();
        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert_eq!(row.destination.to_string(), "0.0.0.0/0");
            assert_eq!(row.table, Some(10001));
            assert!(!row.on_link);
        }
        assert_eq!(
            (rows[0].ifindex, rows[0].next_hop_weight),
            (Some(7), Some(1))
        );
        assert_eq!(
            (rows[1].ifindex, rows[1].next_hop_weight),
            (Some(8), Some(256))
        );
        assert_eq!(rows[1].gateway, Some("fe80::1".parse().unwrap()));
        assert!(!rows[1].flags.contains(&RouteFlag::Up));
    }
}
