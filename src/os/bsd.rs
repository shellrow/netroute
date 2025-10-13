#![allow(non_camel_case_types)]

use crate::{RouteDestination, RouteEntry, RouteFamily, RouteFlag, RouteScope};

use libc::{c_int, pid_t, size_t};
use std::{
    collections::HashMap,
    ffi::c_void,
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

const CTL_NET: c_int = libc::CTL_NET;
const PF_ROUTE: c_int = libc::PF_ROUTE;
const AF_LINK: c_int = libc::AF_LINK;
const AF_INET: c_int = libc::AF_INET;
const AF_INET6: c_int = libc::AF_INET6;

const NET_RT_DUMP: c_int = 1;
// const NET_RT_FLAGS: c_int = 2;

#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
const RTM_VERSION: u8 = 5;
#[cfg(target_os = "netbsd")]
const RTM_VERSION: u8 = 4;

#[cfg(target_os = "freebsd")]
const RTAX_MAX: usize = 8;
#[cfg(target_os = "netbsd")]
const RTAX_MAX: usize = 9;
#[cfg(target_os = "openbsd")]
const RTAX_MAX: usize = 15;

// rtm_flags
const RTF_UP: c_int = 0x0001;
const RTF_GATEWAY: c_int = 0x0002;
const RTF_HOST: c_int = 0x0004;
const RTF_REJECT: c_int = 0x0008;
const RTF_STATIC: c_int = 0x0800;
const RTF_WASCLONED: c_int = 0x20000;

// rtm_addrs
const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_NETMASK: usize = 2;

// sockaddr alignment
const SA_ALIGN: usize = 4;

#[repr(C)]
#[derive(Copy, Clone)]
struct rt_metrics {
    rmx_locks: u32,
    rmx_mtu: u32,
    rmx_hopcount: u32,
    rmx_expire: i32,
    rmx_recvpipe: u32,
    rmx_sendpipe: u32,
    rmx_ssthresh: u32,
    rmx_rtt: u32,
    rmx_rttvar: u32,
    rmx_pksent: u32,
    rmx_weight: u32,
    rmx_nhidx: u32,
    rmx_filler: [u32; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct rt_msghdr {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_flags: c_int,
    rtm_addrs: c_int,
    rtm_pid: pid_t,
    rtm_seq: c_int,
    rtm_errno: c_int,
    rtm_use: c_int,
    rtm_inits: u32,
    rtm_rmx: rt_metrics,
}

unsafe extern "C" {
    fn sysctl(
        name: *mut c_int,
        namelen: u32,
        oldp: *mut c_void,
        oldlenp: *mut size_t,
        newp: *mut c_void,
        newlen: size_t,
    ) -> c_int;
}

#[inline]
fn roundup(len: usize) -> usize {
    if len == 0 {
        SA_ALIGN
    } else {
        (len + (SA_ALIGN - 1)) & !(SA_ALIGN - 1)
    }
}

#[inline]
fn normalize_scoped_v6(gw: Ipv6Addr) -> Ipv6Addr {
    // Normalize link-local IPv6 addresses (e.g., FE80::/10) by stripping the scope ID.
    let seg0 = gw.segments()[0];
    let is_ll = seg0 == 0xfe80;
    let oct = gw.octets();
    let is_mc = oct[0] == 0xff;
    let mc_scope = oct[1] & 0x0f; // 1=node-local, 2=link-local

    if is_ll || (is_mc && (mc_scope == 1 || mc_scope == 2)) {
        let s = gw.segments();
        Ipv6Addr::new(s[0], 0, s[2], s[3], s[4], s[5], s[6], s[7])
    } else {
        gw
    }
}

#[inline]
fn normalize_gateway(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6(normalize_scoped_v6(v6)),
    }
}

/// Fetches a sysctl value into a Vec<u8>.
fn sysctl_vec(mib: &mut [c_int]) -> io::Result<Vec<u8>> {
    let mut len: size_t = 0;
    let mut r = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            ptr::null_mut(),
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buf = vec![0u8; len as usize];
    r = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            buf.as_mut_ptr() as *mut _,
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if r < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOMEM) {
            // If the value grew, kernel returns ENOMEM. Retry once.
            let mut len2: size_t = 0;
            let r2 = unsafe {
                sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as u32,
                    ptr::null_mut(),
                    &mut len2,
                    ptr::null_mut(),
                    0,
                )
            };
            if r2 < 0 {
                return Err(io::Error::last_os_error());
            }
            buf.resize(len2 as usize, 0);
            let r3 = unsafe {
                sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as u32,
                    buf.as_mut_ptr() as *mut _,
                    &mut len2,
                    ptr::null_mut(),
                    0,
                )
            };
            if r3 < 0 {
                return Err(io::Error::last_os_error());
            }
            buf.truncate(len2 as usize);
            return Ok(buf);
        }
        return Err(err);
    }
    buf.truncate(len as usize);
    Ok(buf)
}

/// Extracts an IP address from a sockaddr structure.
fn ip_from_sockaddr(sa: &libc::sockaddr) -> Option<IpAddr> {
    unsafe {
        match sa.sa_family as c_int {
            x if x == AF_INET => {
                let sin = &*(sa as *const _ as *const libc::sockaddr_in);
                let oct = u32::from_be(sin.sin_addr.s_addr).to_be_bytes();
                Some(IpAddr::V4(Ipv4Addr::new(oct[0], oct[1], oct[2], oct[3])))
            }
            x if x == AF_INET6 => {
                let sin6 = &*(sa as *const _ as *const libc::sockaddr_in6);
                let oct = sin6.sin6_addr.s6_addr;
                Some(IpAddr::V6(Ipv6Addr::from(oct)))
            }
            x if x == AF_LINK => None,
            _ => None,
        }
    }
}

fn masklen_from_sockaddr(dst: IpAddr, mask_sa: &libc::sockaddr) -> u8 {
    unsafe {
        let sa_len = mask_sa.sa_len as usize;
        if sa_len == 0 {
            return 0;
        }

        match dst {
            IpAddr::V4(_) => {
                const OFF: usize = 4;
                if sa_len <= OFF {
                    return 0;
                }
                let n = (sa_len - OFF).min(4);
                let base = (mask_sa as *const _ as *const u8).add(OFF);
                let mut bytes = [0u8; 4];
                ptr::copy_nonoverlapping(base, bytes.as_mut_ptr(), n);
                u32::from_be_bytes(bytes).leading_ones() as u8
            }
            IpAddr::V6(_) => {
                const OFF: usize = 8;
                if sa_len <= OFF {
                    return 0;
                }
                let n = (sa_len - OFF).min(16);
                let base = (mask_sa as *const _ as *const u8).add(OFF);
                let mut bytes = [0u8; 16];
                ptr::copy_nonoverlapping(base, bytes.as_mut_ptr(), n);
                u128::from_be_bytes(bytes).leading_ones() as u8
            }
        }
    }
}

#[derive(Debug)]
struct RawRoute {
    dst: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    ifindex: u32,
    #[allow(dead_code)]
    flags: c_int,
}

fn parse_one_route(hdr: &rt_msghdr, addr_block: &[u8]) -> Option<RawRoute> {
    let mut addrs: [Option<*const libc::sockaddr>; RTAX_MAX] = [None; RTAX_MAX];
    let mut off = 0usize;

    for idx in 0..RTAX_MAX {
        if (hdr.rtm_addrs & (1 << idx)) != 0 {
            if off + mem::size_of::<libc::sockaddr>() > addr_block.len() {
                return None;
            }
            let sa = unsafe { &*(addr_block[off..].as_ptr() as *const libc::sockaddr) };
            addrs[idx] = Some(sa as *const libc::sockaddr);

            let sa_len = sa.sa_len as usize;
            let step = roundup(if sa_len == 0 { 0 } else { sa_len });
            if off + step > addr_block.len() {
                return None;
            }
            off += step;
        }
    }

    let dptr = addrs[RTAX_DST]? as *const libc::sockaddr;
    let dst_sa = unsafe { &*dptr };
    let dst_ip = ip_from_sockaddr(dst_sa)?;
    let mut prefix: u8 = match dst_ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if let Some(mptr) = addrs[RTAX_NETMASK] {
        let m_sa = unsafe { &*mptr };
        prefix = if m_sa.sa_len == 0 {
            0
        } else {
            masklen_from_sockaddr(dst_ip, m_sa)
        };
    } else if (hdr.rtm_flags & RTF_HOST) != 0 {
        prefix = match dst_ip {
            IpAddr::V4(_) => 32,
            _ => 128,
        };
    }

    let gateway = if let Some(gptr) = addrs[RTAX_GATEWAY] {
        let g_sa = unsafe { &*gptr };
        ip_from_sockaddr(g_sa).map(normalize_gateway)
    } else {
        None
    };

    Some(RawRoute {
        dst: dst_ip,
        prefix,
        gateway,
        ifindex: hdr.rtm_index as u32,
        flags: hdr.rtm_flags,
    })
}

fn flags_to_letters(f: c_int) -> Vec<RouteFlag> {
    let mut v = Vec::new();
    if f & RTF_UP != 0 {
        v.push(RouteFlag::Up);
    }
    if f & RTF_GATEWAY != 0 {
        v.push(RouteFlag::Gateway);
    }
    if f & RTF_HOST != 0 {
        v.push(RouteFlag::Host);
    }
    if f & RTF_REJECT != 0 {
        v.push(RouteFlag::Reject);
    }
    if f & RTF_STATIC != 0 {
        v.push(RouteFlag::Static);
    }
    v
}

pub fn list_routes_bsd() -> io::Result<Vec<RouteEntry>> {
    let if_map: HashMap<u32, String> = crate::os::unix::unix_interface_map();

    let mut mib = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0];
    let buf = sysctl_vec(&mut mib)?;

    let mut out = Vec::<RouteEntry>::new();
    let mut off = 0usize;

    while off + mem::size_of::<rt_msghdr>() <= buf.len() {
        let p = unsafe { &*(buf[off..].as_ptr() as *const rt_msghdr) };
        let msglen = p.rtm_msglen as usize;
        if msglen == 0 || off + msglen > buf.len() {
            break;
        }

        if p.rtm_version != RTM_VERSION {
            off += msglen;
            continue;
        }
        if (p.rtm_flags & RTF_WASCLONED) != 0 {
            off += msglen;
            continue;
        }
        if p.rtm_errno != 0 {
            off += msglen;
            continue;
        }

        let ab = &buf[off + mem::size_of::<rt_msghdr>()..off + msglen];

        if let Some(rr) = parse_one_route(p, ab) {
            let family = match rr.dst {
                IpAddr::V4(_) => RouteFamily::Ipv4,
                IpAddr::V6(_) => RouteFamily::Ipv6,
            };
            let destination = RouteDestination::new(rr.dst, rr.prefix);
            let on_link = rr.gateway.is_none();
            let gateway = rr.gateway;
            let flags = flags_to_letters(p.rtm_flags);
            let scope = Some(if on_link {
                RouteScope::Link
            } else {
                RouteScope::Global
            });

            let ifindex = Some(rr.ifindex);
            let ifname = ifindex.and_then(|i| if_map.get(&i).cloned());

            out.push(RouteEntry {
                family,
                destination,
                gateway,
                on_link,
                ifindex,
                ifname,
                metric: None,
                flags,
                protocol: None,
                scope,
                table: None,
                lifetime_ms: None,
            });
        }

        off += msglen;
    }

    Ok(out)
}
