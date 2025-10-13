#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub(crate) mod bsd;
#[cfg(target_vendor = "apple")]
pub(crate) mod darwin;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod linux;
#[cfg(target_family = "unix")]
pub(crate) mod unix;
#[cfg(target_os = "windows")]
pub(crate) mod windows;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub use bsd::list_routes_bsd as list_routes;
#[cfg(target_vendor = "apple")]
pub(crate) use darwin::list_routes_macos as list_routes;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::list_routes_linux as list_routes;
#[cfg(target_os = "windows")]
pub(crate) use windows::list_routes_windows as list_routes;
