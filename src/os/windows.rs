use std::{collections::HashMap, ffi::CStr, io, net::IpAddr, ptr};

use windows_sys::Win32::{
    Foundation::NO_ERROR,
    NetworkManagement::IpHelper::{
        FreeMibTable, GAA_FLAG_INCLUDE_ALL_INTERFACES, GetAdaptersAddresses, GetIpForwardTable2,
        IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, NL_ROUTE_PROTOCOL, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    },
};

use crate::{RouteDestination, RouteEntry, RouteFamily, RouteFlag, RouteProtocol, RouteScope};

// Note: We take `&*mut T` instead of just `*mut T` to tie the lifetime of all the returned items
// to the lifetime of the pointer for some extra safety.
unsafe fn linked_list_iter<T>(ptr: &*mut T, next: fn(&T) -> *mut T) -> impl Iterator<Item = &T> {
    let mut ptr = ptr.cast_const();

    std::iter::from_fn(move || {
        let cur = unsafe { ptr.as_ref()? };
        ptr = next(cur);
        Some(cur)
    })
}

// The `Next` element is always the same, so use a macro to avoid the repetition.
macro_rules! linked_list_iter {
    ($ptr:expr) => {
        linked_list_iter($ptr, |cur| cur.Next)
    };
}

fn ip_from_sockaddr(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    unsafe {
        match sa.si_family {
            AF_INET => {
                let v4: &SOCKADDR_IN = &sa.Ipv4;
                let octets = v4.sin_addr.S_un.S_addr.to_ne_bytes();
                Some(IpAddr::from(octets))
            }
            AF_INET6 => {
                let v6: &SOCKADDR_IN6 = &sa.Ipv6;
                let o = v6.sin6_addr.u.Byte;
                let octets = [
                    o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11],
                    o[12], o[13], o[14], o[15],
                ];
                Some(IpAddr::from(octets))
            }
            _ => None,
        }
    }
}

fn cidr_from_prefix(
    prefix: &windows_sys::Win32::NetworkManagement::IpHelper::IP_ADDRESS_PREFIX,
) -> Option<(IpAddr, u8)> {
    let ip = ip_from_sockaddr(&prefix.Prefix)?;
    let len = prefix.PrefixLength;
    Some((ip, len))
}

fn is_zero_addr(sa: &SOCKADDR_INET) -> bool {
    unsafe {
        match sa.si_family {
            AF_INET => sa.Ipv4.sin_addr.S_un.S_addr == 0,
            AF_INET6 => {
                let b = sa.Ipv6.sin6_addr.u.Byte;
                b.iter().all(|x| *x == 0)
            }
            _ => true,
        }
    }
}

fn ifindex_name_map() -> io::Result<HashMap<u32, String>> {
    let mut map = HashMap::new();
    let mut buf_len: u32 = 0;
    let _ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut buf_len,
        )
    };

    let mut buf: Vec<u8> = vec![0; buf_len as usize];
    let p_addrs = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES,
            ptr::null_mut(),
            p_addrs,
            &mut buf_len,
        )
    };
    if ret != NO_ERROR {
        return Err(io::Error::last_os_error());
    }

    unsafe { linked_list_iter!(&p_addrs) }
        .filter_map(|cur| {
            let index = {
                let anon1 = cur.Anonymous1;
                let anon = unsafe { &anon1.Anonymous };
                anon.IfIndex
            };
            let adapter_name = unsafe { CStr::from_ptr(cur.AdapterName.cast()) }
                .to_string_lossy()
                .into_owned();
            Some((index, adapter_name))
        })
        .for_each(|(index, adapter_name)| {
            map.insert(index, adapter_name);
        });

    Ok(map)
}

fn proto_to_route_protocol(p: NL_ROUTE_PROTOCOL) -> Option<RouteProtocol> {
    use windows_sys::Win32::Networking::WinSock as winsock;

    let proto = match p {
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
        _ => return None,
    };

    Some(proto)
}

fn normalize_flags(row: &MIB_IPFORWARD_ROW2, on_link: bool) -> Vec<RouteFlag> {
    let mut v = vec![RouteFlag::Up];
    if !on_link {
        v.push(RouteFlag::Gateway);
    }
    if row.Loopback != 0 {
        v.push(RouteFlag::Loopback);
    }
    v
}

fn scope(on_link: bool) -> Option<RouteScope> {
    Some(if on_link {
        RouteScope::Link
    } else {
        RouteScope::Global
    })
}

pub fn list_routes_windows() -> io::Result<Vec<RouteEntry>> {
    let ifmap = ifindex_name_map().unwrap_or_default();

    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    let ret = unsafe { GetIpForwardTable2(AF_UNSPEC as u16, &mut table) };
    if ret != NO_ERROR {
        return Err(io::Error::last_os_error());
    }

    // Guard to free the table when we exit this function
    struct TableGuard(*mut core::ffi::c_void);
    impl Drop for TableGuard {
        fn drop(&mut self) {
            unsafe { FreeMibTable(self.0) }
        }
    }
    let _guard = TableGuard(table as _);

    let mut out = Vec::new();

    unsafe {
        let count = (*table).NumEntries as usize;

        let rows: &[MIB_IPFORWARD_ROW2] =
            std::slice::from_raw_parts((*table).Table.as_ptr(), count);

        for row in rows {
            let (dst_ip, prefix_len) = match cidr_from_prefix(&row.DestinationPrefix) {
                Some(x) => x,
                None => continue,
            };

            let next_hop = ip_from_sockaddr(&row.NextHop);
            let on_link = next_hop.is_none() || is_zero_addr(&row.NextHop);

            let family = match row.DestinationPrefix.Prefix.si_family {
                AF_INET => RouteFamily::Ipv4,
                AF_INET6 => RouteFamily::Ipv6,
                _ => continue,
            };

            let destination = RouteDestination::new(dst_ip, prefix_len);

            let gateway = if on_link { None } else { next_hop };

            let ifindex = Some(row.InterfaceIndex);
            let ifname = ifindex.and_then(|idx| ifmap.get(&idx).cloned());

            let metric = Some(row.Metric);
            let protocol = proto_to_route_protocol(row.Protocol);

            let flags = normalize_flags(row, on_link);
            let scope = scope(on_link);

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
                table: None,
                lifetime_ms: None,
            });
        }
    }

    Ok(out)
}
