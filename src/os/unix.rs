use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::os::raw::c_char;

pub fn unix_interface_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let mut seen = HashSet::new();
    let mut addrs: MaybeUninit<*mut libc::ifaddrs> = MaybeUninit::uninit();
    if unsafe { libc::getifaddrs(addrs.as_mut_ptr()) } != 0 {
        return HashMap::new();
    }
    let addrs = unsafe { addrs.assume_init() };
    let mut addr = addrs;
    while !addr.is_null() {
        let addr_ref: &libc::ifaddrs = unsafe { &*addr };
        let c_str = addr_ref.ifa_name as *const c_char;
        let bytes = unsafe { CStr::from_ptr(c_str).to_bytes() };
        let name = String::from_utf8_lossy(bytes).into_owned();
        // getifaddrs returns one entry per address. Deduplicate by interface name.
        if seen.insert(name.clone())
            && let Ok(c_name) = CString::new(name.as_str())
        {
            let if_index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
            if if_index != 0 {
                map.insert(if_index as u32, name);
            }
        }
        addr = addr_ref.ifa_next;
    }
    unsafe {
        libc::freeifaddrs(addrs);
    }
    map
}
