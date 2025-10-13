#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_family = "unix")]
pub(crate) mod unix;
#[cfg(target_os = "windows")]
pub(crate) mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::list_routes_linux as list_routes;
#[cfg(target_os = "macos")]
pub(crate) use macos::list_routes_macos as list_routes;
#[cfg(target_os = "windows")]
pub(crate) use windows::list_routes_windows as list_routes;
