mod os;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RouteEntry {
    pub family: u8,
    pub dst: String,
    pub gateway: Option<String>,
    pub on_link: bool,
    pub ifindex: Option<u32>,
    pub ifname: Option<String>,
    pub metric: Option<u32>,
    pub flags: Vec<String>,
    pub proto: Option<String>,
    pub scope: Option<String>,
    pub table: Option<u32>,
    pub lifetime_ms: Option<u64>,
}

pub fn list_routes() -> std::io::Result<Vec<RouteEntry>> {
    os::list_routes()
}
