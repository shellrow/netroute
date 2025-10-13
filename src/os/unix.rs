use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::str::from_utf8_unchecked;

pub fn unix_interface_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let mut names: Vec<String> = Vec::new();
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
        let name = unsafe { from_utf8_unchecked(bytes).to_owned() };
        // Check if there is already an interface with this name (since getifaddrs returns one
        // entry per address, so if the interface has multiple addresses, it returns multiple entries).
        if !names.contains(&name) {
            names.push(name);
        }
        addr = addr_ref.ifa_next;
    }
    unsafe {
        libc::freeifaddrs(addrs);
    }
    for name in names {
        let c_name = CString::new(name.clone()).unwrap();
        let if_index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if if_index != 0 {
            map.insert(if_index as u32, name);
        }
    }
    map
}
