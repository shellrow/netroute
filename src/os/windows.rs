use std::{collections::HashMap, io, net::IpAddr, ptr};

use windows_sys::Win32::{
    Foundation::NO_ERROR,
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceLuidToAlias, FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2,
            MIB_IPFORWARD_TABLE2,
        },
        Ndis::{IF_MAX_STRING_SIZE, NET_LUID_LH},
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, NL_ROUTE_PROTOCOL, SOCKADDR_INET},
};

use crate::{RouteDestination, RouteEntry, RouteFamily, RouteFlag, RouteProtocol};

fn ip(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    // The address family selects the active SOCKADDR_INET union member.
    unsafe {
        match sa.si_family {
            AF_INET => Some(sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes().into()),
            AF_INET6 => Some(sa.Ipv6.sin6_addr.u.Byte.into()),
            _ => None,
        }
    }
}

fn scope_id(sa: &SOCKADDR_INET) -> Option<u32> {
    // Only IPv6 addresses have a scope ID.
    if unsafe { sa.si_family } != AF_INET6 {
        return None;
    }
    let id = unsafe { sa.Ipv6.Anonymous.sin6_scope_id };
    (id != 0).then_some(id)
}

fn interface_alias(luid: &NET_LUID_LH) -> Option<String> {
    let mut name = [0u16; IF_MAX_STRING_SIZE as usize + 1];
    if unsafe { ConvertInterfaceLuidToAlias(luid, name.as_mut_ptr(), name.len()) } != NO_ERROR {
        return None;
    }
    let len = name.iter().position(|c| *c == 0)?;
    Some(String::from_utf16_lossy(&name[..len]))
}

fn proto_to_route_protocol(p: NL_ROUTE_PROTOCOL) -> RouteProtocol {
    use windows_sys::Win32::Networking::WinSock as winsock;

    match p {
        winsock::MIB_IPPROTO_OTHER => RouteProtocol::Other("other".into()),
        winsock::MIB_IPPROTO_LOCAL => RouteProtocol::Local,
        winsock::MIB_IPPROTO_NETMGMT => RouteProtocol::NetMgmt,
        winsock::MIB_IPPROTO_ICMP => RouteProtocol::Icmp,
        winsock::MIB_IPPROTO_EGP => RouteProtocol::Egp,
        winsock::MIB_IPPROTO_GGP => RouteProtocol::Ggp,
        winsock::MIB_IPPROTO_HELLO => RouteProtocol::Hello,
        winsock::MIB_IPPROTO_RIP => RouteProtocol::Rip,
        winsock::MIB_IPPROTO_IS_IS => RouteProtocol::Isis,
        winsock::MIB_IPPROTO_ES_IS => RouteProtocol::Esis,
        winsock::MIB_IPPROTO_CISCO => RouteProtocol::Cisco,
        winsock::MIB_IPPROTO_BBN => RouteProtocol::Bbn,
        winsock::MIB_IPPROTO_OSPF => RouteProtocol::Ospf,
        winsock::MIB_IPPROTO_BGP => RouteProtocol::Bgp,
        winsock::MIB_IPPROTO_NT_AUTOSTATIC => RouteProtocol::Autostatic,
        winsock::MIB_IPPROTO_NT_STATIC => RouteProtocol::Static,
        winsock::MIB_IPPROTO_NT_STATIC_NON_DOD => RouteProtocol::StaticNonDod,
        winsock::MIB_IPPROTO_DHCP => RouteProtocol::Dhcp,
        winsock::MIB_IPPROTO_RPL => RouteProtocol::Rpl,
        _ => RouteProtocol::Other(p.to_string()),
    }
}

struct Table(*mut MIB_IPFORWARD_TABLE2);

impl Drop for Table {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.0.cast()) }
    }
}

fn entry(
    row: &MIB_IPFORWARD_ROW2,
    names: &mut HashMap<u64, Option<String>>,
) -> io::Result<RouteEntry> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid IP forwarding row");
    let dst = ip(&row.DestinationPrefix.Prefix).ok_or_else(invalid)?;
    let prefix = row.DestinationPrefix.PrefixLength;
    let width = if dst.is_ipv4() { 32 } else { 128 };
    if prefix > width {
        return Err(invalid());
    }
    let gateway = ip(&row.NextHop).ok_or_else(invalid)?;
    let gateway = (!gateway.is_unspecified()).then_some(gateway);
    let mut flags = vec![RouteFlag::Up];
    if gateway.is_some() {
        flags.push(RouteFlag::Gateway);
    }
    if row.Loopback {
        flags.push(RouteFlag::Loopback);
    }
    if prefix == width {
        flags.push(RouteFlag::Host);
    }
    let name = names
        .entry(unsafe { row.InterfaceLuid.Value })
        .or_insert_with(|| interface_alias(&row.InterfaceLuid));
    Ok(RouteEntry {
        family: RouteFamily::from(dst),
        destination: RouteDestination::new(dst, prefix),
        source: None,
        destination_scope_id: scope_id(&row.DestinationPrefix.Prefix),
        gateway_scope_id: gateway.and_then(|_| scope_id(&row.NextHop)),
        next_hop_id: None,
        next_hop_weight: None,
        gateway,
        on_link: gateway.is_none(),
        ifindex: (row.InterfaceIndex != 0).then_some(row.InterfaceIndex),
        ifname: name.clone(),
        metric: (row.Metric != u32::MAX).then_some(row.Metric),
        flags,
        protocol: Some(proto_to_route_protocol(row.Protocol)),
        scope: None,
        table: None,
        lifetime_ms: (!row.Immortal && row.ValidLifetime != u32::MAX)
            .then_some(u64::from(row.ValidLifetime) * 1000),
    })
}

pub(crate) fn list_routes() -> io::Result<Vec<RouteEntry>> {
    let mut ptr = ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut ptr) };
    if status != NO_ERROR {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let table = Table(ptr);
    // The allocation contains NumEntries aligned rows after the table header.
    // Take the address of the flexible array without referencing its first row.
    let rows = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*table.0).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table.0).NumEntries as usize,
        )
    };
    let mut names = HashMap::new();
    rows.iter().map(|row| entry(row, &mut names)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_link_host_route_has_no_gateway_and_converts_lifetime() {
        let mut row = MIB_IPFORWARD_ROW2::default();
        row.DestinationPrefix.Prefix.si_family = AF_INET6;
        row.DestinationPrefix.PrefixLength = 128;
        row.NextHop.si_family = AF_INET6;
        row.ValidLifetime = 30;
        row.Loopback = true;
        let mut names = HashMap::from([(0, Some("Loopback".into()))]);
        let route = entry(&row, &mut names).unwrap();
        assert!(route.on_link);
        assert_eq!(route.gateway, None);
        assert_eq!(route.lifetime_ms, Some(30_000));
        assert!(route.flags.contains(&RouteFlag::Loopback));
        assert!(route.flags.contains(&RouteFlag::Host));
        row.ValidLifetime = u32::MAX;
        assert_eq!(entry(&row, &mut names).unwrap().lifetime_ms, None);
        row.DestinationPrefix.PrefixLength = 129;
        assert_eq!(
            entry(&row, &mut names).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
