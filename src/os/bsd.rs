use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

use super::unix::InterfaceNames;
use crate::{RouteDestination, RouteEntry, RouteFamily, RouteFlag};

// Routing socket ABI from <net/route.h>. Darwin rounds sockaddrs to four
// bytes even in 64-bit processes. NetBSD uses eight on both word sizes.
#[cfg(target_vendor = "apple")]
const ALIGN: usize = 4;
#[cfg(target_os = "netbsd")]
const ALIGN: usize = 8;
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
const ALIGN: usize = size_of::<libc::c_long>();

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn read_dump(mib: &mut [libc::c_int]) -> io::Result<Vec<u8>> {
    for attempt in 0..3 {
        let mut len = 0;
        let mut read = |dst, len: &mut usize| {
            // sysctl reads the MIB and writes at most the supplied buffer length.
            let status = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as _,
                    dst,
                    len,
                    ptr::null_mut(),
                    0,
                )
            };
            if status == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        };
        read(ptr::null_mut(), &mut len)?;
        let mut buf = vec![0; len];
        match read(buf.as_mut_ptr().cast(), &mut len) {
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) && attempt < 2 => continue,
            Err(e) => return Err(e),
            Ok(()) if len > buf.len() => return Err(invalid("invalid sysctl result length")),
            Ok(()) => {
                buf.truncate(len);
                return Ok(buf);
            }
        }
    }
    unreachable!()
}

struct Header {
    len: usize,
    index: u16,
    flags: i32,
    addrs: i32,
    table: Option<u32>,
    metric: Option<u32>,
}

impl Header {
    fn parse(msg: &[u8]) -> io::Result<Self> {
        // Only the fixed fields below are accessed. OpenBSD supplies the
        // address-block offset; the other kernels use sizeof(rt_msghdr).
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let len = size_of::<libc::rt_msghdr>();
        // XNU's v5 header is 92 bytes on the other Apple targets, where
        // libc does not expose rt_msghdr. NetBSD v4 aligns metrics to 8 bytes.
        #[cfg(all(target_vendor = "apple", not(target_os = "macos")))]
        let len = 92;
        #[cfg(target_os = "netbsd")]
        let len = 120;
        #[cfg(target_os = "openbsd")]
        let len = u16::from_ne_bytes(
            msg.get(4..6)
                .ok_or_else(|| invalid("short route header"))?
                .try_into()
                .unwrap(),
        ) as usize;
        if len < 36 || msg.len() < len {
            return Err(invalid("invalid route header length"));
        }
        let u16_at = |i| u16::from_ne_bytes(msg[i..i + 2].try_into().unwrap());
        let i32_at = |i| i32::from_ne_bytes(msg[i..i + 4].try_into().unwrap());
        #[cfg(target_os = "openbsd")]
        let (index, flags, table, metric) = (
            u16_at(6),
            i32_at(16),
            Some(u32::from(u16_at(8))),
            Some(u32::from(msg[10])),
        );
        #[cfg(not(target_os = "openbsd"))]
        let (index, flags, table, metric) = (u16_at(4), i32_at(8), None, None);
        let errno = i32_at(if cfg!(target_os = "openbsd") { 32 } else { 24 });
        if errno != 0 {
            return Err(io::Error::from_raw_os_error(errno));
        }
        Ok(Self {
            len,
            index,
            flags,
            addrs: i32_at(12),
            table,
            metric,
        })
    }
}

fn sockaddr<'a>(data: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let len = usize::from(*data.first().ok_or_else(|| invalid("missing sockaddr"))?);
    let step = len.max(1).next_multiple_of(ALIGN);
    let (slot, rest) = data
        .split_at_checked(step)
        .ok_or_else(|| invalid("truncated sockaddr"))?;
    *data = rest;
    Ok(&slot[..len])
}

#[derive(Debug, PartialEq)]
struct ScopedIp {
    addr: IpAddr,
    scope_id: Option<u32>,
}

fn ip(addr: &[u8]) -> io::Result<Option<ScopedIp>> {
    match i32::from(
        *addr
            .get(1)
            .ok_or_else(|| invalid("missing sockaddr family"))?,
    ) {
        libc::AF_INET => {
            let bytes: [u8; 4] = addr
                .get(4..8)
                .ok_or_else(|| invalid("short IPv4 sockaddr"))?
                .try_into()
                .unwrap();
            Ok(Some(ScopedIp {
                addr: Ipv4Addr::from(bytes).into(),
                scope_id: None,
            }))
        }
        libc::AF_INET6 => {
            let mut bytes: [u8; 16] = addr
                .get(8..24)
                .ok_or_else(|| invalid("short IPv6 sockaddr"))?
                .try_into()
                .unwrap();
            // KAME encodes the interface zone in the second 16-bit word.
            let embedded = if (bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80)
                || (bytes[0] == 0xff && matches!(bytes[1] & 0x0f, 1 | 2))
            {
                let zone = u16::from_be_bytes([bytes[2], bytes[3]]);
                bytes[2..4].fill(0);
                u32::from(zone)
            } else {
                0
            };
            let explicit = addr
                .get(24..28)
                .map(|id| u32::from_ne_bytes(id.try_into().unwrap()))
                .unwrap_or(0);
            let zone = if explicit != 0 { explicit } else { embedded };
            Ok(Some(ScopedIp {
                addr: Ipv6Addr::from(bytes).into(),
                scope_id: (zone != 0).then_some(zone),
            }))
        }
        _ => Ok(None),
    }
}

fn prefix_len(dst: IpAddr, mask: &[u8]) -> Option<u8> {
    let (offset, width) = if dst.is_ipv4() { (4, 4) } else { (8, 16) };
    let mut bytes = [0; 16];
    // A compact mask omits trailing zero bytes, including the entire /0.
    let mask = mask.get(offset..).unwrap_or_default();
    let n = mask.len().min(width);
    bytes[..n].copy_from_slice(&mask[..n]);
    let bits = u128::from_be_bytes(bytes);
    let prefix = bits.leading_ones();
    // CIDR cannot represent non-contiguous BSD masks.
    (bits.count_ones() == prefix).then_some(prefix as u8)
}

// The common flag values are part of the routing socket ABI on all four systems.
const UP: i32 = 0x1;
const GATEWAY: i32 = 0x2;
const HOST: i32 = 0x4;
const REJECT: i32 = 0x8;
const STATIC: i32 = 0x800;
const BLACKHOLE: i32 = 0x1000;

fn parse_dump(mut data: &[u8]) -> io::Result<Vec<RouteEntry>> {
    let mut names = InterfaceNames::default();
    let mut out = Vec::new();
    while !data.is_empty() {
        let len = u16::from_ne_bytes(
            data.get(..2)
                .ok_or_else(|| invalid("short route message"))?
                .try_into()
                .unwrap(),
        ) as usize;
        let (msg, rest) = data
            .split_at_checked(len)
            .ok_or_else(|| invalid("truncated route message"))?;
        data = rest;
        #[cfg(target_os = "netbsd")]
        const VERSION: u8 = 4;
        #[cfg(not(target_os = "netbsd"))]
        const VERSION: u8 = 5;
        if msg.get(2) != Some(&VERSION) {
            return Err(invalid("unexpected routing message version"));
        }
        let h = Header::parse(msg)?;
        // Darwin marks cloned cache entries with RTF_WASCLONED.
        #[cfg(target_vendor = "apple")]
        if h.flags & 0x20000 != 0 {
            continue;
        }
        #[cfg(target_os = "openbsd")]
        if h.flags & libc::RTF_CLONED != 0 {
            continue;
        }
        let mut remaining = &msg[h.len..];
        let mut addrs = [None; 3];
        let mut present = h.addrs as u32;
        while present != 0 {
            let index = present.trailing_zeros() as usize;
            let addr = sockaddr(&mut remaining)?;
            if let Some(slot) = addrs.get_mut(index) {
                *slot = Some(addr);
            }
            present &= present - 1;
        }
        let Some(ScopedIp {
            addr: dst,
            scope_id: destination_scope_id,
        }) = ip(addrs[0].ok_or_else(|| invalid("missing route destination"))?)?
        else {
            continue;
        };
        let host = h.flags & HOST != 0;
        let prefix = if host || addrs[2].is_none() {
            if dst.is_ipv4() { 32 } else { 128 }
        } else {
            let Some(n) = prefix_len(dst, addrs[2].unwrap_or_default()) else {
                continue;
            };
            n
        };
        let via_router = h.flags & GATEWAY != 0;
        let reject = h.flags & (REJECT | BLACKHOLE) != 0;
        let gateway = if via_router {
            addrs[1].map(ip).transpose()?.flatten()
        } else {
            None
        };
        let mut flags = Vec::new();
        for (present, flag) in [
            (h.flags & UP != 0, RouteFlag::Up),
            (via_router, RouteFlag::Gateway),
            (host, RouteFlag::Host),
            (reject, RouteFlag::Reject),
            (h.flags & STATIC != 0, RouteFlag::Static),
        ] {
            if present {
                flags.push(flag);
            }
        }
        let ifindex = (h.index != 0).then_some(u32::from(h.index));
        out.push(RouteEntry {
            family: RouteFamily::from(dst),
            destination: RouteDestination::new(dst, prefix),
            source: None,
            next_hop_id: None,
            next_hop_weight: None,
            destination_scope_id,
            gateway_scope_id: gateway.as_ref().and_then(|g| g.scope_id),
            gateway: gateway.map(|g| g.addr),
            on_link: !via_router && !reject,
            ifindex,
            ifname: ifindex.and_then(|i| names.lookup(i)),
            metric: h.metric,
            flags,
            protocol: None,
            scope: None,
            table: h.table,
            lifetime_ms: None,
        });
    }
    Ok(out)
}

pub(crate) fn list_routes() -> io::Result<Vec<RouteEntry>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        0,
        libc::NET_RT_DUMP,
        0,
        #[cfg(target_os = "openbsd")]
        {
            unsafe extern "C" {
                fn getrtable() -> libc::c_int;
            }
            // Select the calling process's routing domain.
            unsafe { getrtable() }
        },
    ];
    parse_dump(&read_dump(&mut mib)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_masks_do_not_read_the_next_sockaddr() {
        let addr = Ipv4Addr::UNSPECIFIED.into();
        assert_eq!(prefix_len(addr, &[]), Some(0));
        assert_eq!(prefix_len(addr, &[7, 0, 0, 0, 255, 255, 240]), Some(20));
        assert_eq!(prefix_len(addr, &[7, 0, 0, 0, 255, 0, 255]), None);
        let mut mask = [0u8; 17];
        mask[8..16].fill(255);
        mask[16] = 128;
        assert_eq!(prefix_len(Ipv6Addr::UNSPECIFIED.into(), &mask), Some(65));
    }

    #[test]
    fn scoped_addresses_keep_the_zone_separate() {
        let mut addr = [0; 28];
        addr[0] = 28;
        addr[1] = libc::AF_INET6 as u8;
        addr[8..12].copy_from_slice(&[0xfe, 0x80, 0, 42]);
        addr[23] = 1;
        let mut expected = ScopedIp {
            addr: "fe80::1".parse().unwrap(),
            scope_id: Some(42),
        };
        assert_eq!(ip(&addr).unwrap(), Some(expected));
        addr[24..28].copy_from_slice(&72u32.to_ne_bytes());
        expected = ScopedIp {
            addr: "fe80::1".parse().unwrap(),
            scope_id: Some(72),
        };
        assert_eq!(ip(&addr).unwrap(), Some(expected));
    }

    #[test]
    fn decodes_default_route_from_native_header_and_compact_mask() {
        #[cfg(target_os = "openbsd")]
        let header_len = 96;
        #[cfg(target_os = "netbsd")]
        let header_len = 120;
        #[cfg(target_os = "freebsd")]
        let header_len = 32 + 15 * size_of::<libc::c_ulong>();
        #[cfg(target_vendor = "apple")]
        let header_len = 92;
        let mut msg = vec![0; header_len];
        msg[2] = if cfg!(target_os = "netbsd") { 4 } else { 5 };
        msg[3] = 4; // RTM_GET
        let (index_offset, flags_offset) = if cfg!(target_os = "openbsd") {
            msg[4..6].copy_from_slice(&(header_len as u16).to_ne_bytes());
            (6, 16)
        } else {
            (4, 8)
        };
        msg[index_offset..index_offset + 2].copy_from_slice(&9u16.to_ne_bytes());
        msg[flags_offset..flags_offset + 4].copy_from_slice(&(UP | GATEWAY).to_ne_bytes());
        msg[12..16].copy_from_slice(&7i32.to_ne_bytes());
        for address in [[0; 4], [192, 0, 2, 1]] {
            let mut sa = [0; 16];
            sa[0] = 16;
            sa[1] = libc::AF_INET as u8;
            sa[4..8].copy_from_slice(&address);
            msg.extend_from_slice(&sa);
        }
        msg.resize(msg.len() + ALIGN, 0);
        let len = msg.len() as u16;
        msg[..2].copy_from_slice(&len.to_ne_bytes());
        let routes = parse_dump(&msg).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination.to_string(), "0.0.0.0/0");
        assert_eq!(routes[0].gateway, Some([192, 0, 2, 1].into()));
        assert_eq!(routes[0].ifindex, Some(9));
        // A short last message must invalidate the whole dump.
        msg.extend_from_slice(&[1, 0]);
        assert_eq!(
            parse_dump(&msg).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn sockaddr_lengths_are_bounded_by_the_message() {
        let bytes = [12, libc::AF_INET as u8, 0, 0];
        assert!(sockaddr(&mut &bytes[..]).is_err());
        assert!(ip(&bytes).is_err());
        assert!(parse_dump(&[0, 0]).is_err());
        assert!(parse_dump(&[]).unwrap().is_empty());
    }
}
