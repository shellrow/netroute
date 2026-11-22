#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
mod bsd;
#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub(crate) use bsd::list_routes;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::list_routes;

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "linux",
    target_os = "android"
))]
mod unix;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::list_routes;

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "linux",
    target_os = "android",
    windows
)))]
pub(crate) fn list_routes() -> std::io::Result<Vec<crate::RouteEntry>> {
    Err(std::io::ErrorKind::Unsupported.into())
}
