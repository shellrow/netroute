#![allow(non_camel_case_types)]

use libc::{c_char, c_int, c_uchar, pid_t, size_t};
use std::{
    collections::HashMap,
    ffi::c_void,
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

use crate::{RouteDestination, RouteEntry, RouteFamily, RouteFlag, RouteScope};

const CTL_NET: c_int = 4;
//const AF_ROUTE: c_int = 17;
const PF_ROUTE: c_int = 17;
const AF_LINK: c_int = 18;
const AF_INET: c_int = 2;
const AF_INET6: c_int = 30;

const NET_RT_DUMP: c_int = 1;
// const NET_RT_FLAGS: c_int = 2;

const RTM_VERSION: c_uchar = 5;

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
const RTAX_MAX: usize = 8;

#[repr(C)]
#[derive(Copy, Clone)]
struct sockaddr {
    sa_len: c_uchar,
    sa_family: c_uchar,
    sa_data: [c_char; 14],
}
#[repr(C)]
#[derive(Copy, Clone)]
struct in_addr {
    s_addr: u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
struct in6_addr {
    __u6_addr: in6_addr_bind,
}
#[repr(C)]
#[derive(Copy, Clone)]
union in6_addr_bind {
    __u6_addr8: [u8; 16],
    __u6_addr16: [u16; 8],
    __u6_addr32: [u32; 4],
}
#[repr(C)]
#[derive(Copy, Clone)]
struct sockaddr_in {
    sin_len: c_uchar,
    sin_family: c_uchar,
    sin_port: u16,
    sin_addr: in_addr,
    sin_zero: [c_char; 8],
}
#[repr(C)]
#[derive(Copy, Clone)]
struct sockaddr_in6 {
    sin6_len: c_uchar,
    sin6_family: c_uchar,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: in6_addr,
    sin6_scope_id: u32,
}

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
    rmx_state: u32,
    rmx_filler: [u32; 3],
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

fn roundup(len: usize) -> usize {
    if len == 0 { 4 } else { ((len - 1) | 3) + 1 }
}

fn ip_from_sockaddr(sa: &sockaddr) -> Option<IpAddr> {
    unsafe {
        match sa.sa_family as c_int {
            AF_INET => {
                let sin: &sockaddr_in = &*(sa as *const _ as *const sockaddr_in);
                let oct = sin.sin_addr.s_addr.to_ne_bytes();
                Some(IpAddr::V4(Ipv4Addr::new(oct[0], oct[1], oct[2], oct[3])))
            }
            AF_INET6 => {
                let sin6: &sockaddr_in6 = &*(sa as *const _ as *const sockaddr_in6);
                let b = sin6.sin6_addr.__u6_addr.__u6_addr8;
                let octets = [
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
                    b[12], b[13], b[14], b[15],
                ];
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            AF_LINK => None,
            _ => None,
        }
    }
}

fn masklen_from_sockaddr(dst: IpAddr, mask_sa: &sockaddr) -> u8 {
    unsafe {
        match dst {
            IpAddr::V4(_) => {
                let m: &sockaddr_in = &*(mask_sa as *const _ as *const sockaddr_in);
                u32::from_be(m.sin_addr.s_addr).leading_ones() as u8
            }
            IpAddr::V6(_) => {
                let m: &sockaddr_in6 = &*(mask_sa as *const _ as *const sockaddr_in6);
                let b = m.sin6_addr.__u6_addr.__u6_addr8;
                let v = u128::from_be_bytes(b);
                v.leading_ones() as u8
            }
        }
    }
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
    let mut addrs: [Option<*const sockaddr>; RTAX_MAX] = [None; RTAX_MAX];
    let mut off = 0usize;

    for idx in 0..RTAX_MAX {
        if (hdr.rtm_addrs & (1 << idx)) != 0 {
            if off + mem::size_of::<sockaddr>() > addr_block.len() {
                return None;
            }
            let sa = unsafe { &*(addr_block[off..].as_ptr() as *const sockaddr) };
            addrs[idx] = Some(sa as *const sockaddr);

            let sa_len = sa.sa_len as usize;
            let step = roundup(if sa_len == 0 { 0 } else { sa_len });
            if off + step > addr_block.len() {
                return None;
            }
            off += step;
        }
    }

    let dptr = addrs[RTAX_DST]? as *const sockaddr;
    let dst_sa = unsafe { &*dptr };
    let dst_ip = ip_from_sockaddr(dst_sa)?;
    let mut prefix: u8 = match dst_ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if let Some(mptr) = addrs[RTAX_NETMASK] {
        let m_sa = unsafe { &*mptr };
        // sa_len==0 is possible for default route
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

    // gateway
    let gateway = if let Some(gptr) = addrs[RTAX_GATEWAY] {
        let g_sa = unsafe { &*gptr };
        ip_from_sockaddr(g_sa)
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

pub fn list_routes_macos() -> io::Result<Vec<RouteEntry>> {
    let if_map: HashMap<u32, String> = crate::os::unix::unix_interface_map();

    let mut mib: [c_int; 6] = [0; 6];
    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = 0;
    mib[4] = NET_RT_DUMP;
    mib[5] = 0;

    let mut len: size_t = 0;
    let r = unsafe {
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
    let r = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            buf.as_mut_ptr() as *mut c_void,
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut out = Vec::<RouteEntry>::new();
    let mut off = 0usize;

    while off + mem::size_of::<rt_msghdr>() <= len as usize {
        let p = unsafe { &*(buf[off..].as_ptr() as *const rt_msghdr) };
        if p.rtm_version != RTM_VERSION {
            if p.rtm_msglen == 0 {
                break;
            }
            off += p.rtm_msglen as usize;
            continue;
        }
        let msglen = p.rtm_msglen as usize;
        if msglen == 0 || off + msglen > len as usize {
            break;
        }

        if (p.rtm_flags & RTF_WASCLONED) != 0 {
            off += msglen;
            continue;
        }

        let addr_block = &buf[off + mem::size_of::<rt_msghdr>()..off + msglen];

        if let Some(rr) = parse_one_route(p, addr_block) {
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
