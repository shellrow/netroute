#[cfg(feature = "serde")]
use netroute::RouteEntry;
use netroute::{RouteFamily, list_routes};

#[test]
fn concurrent_snapshots_have_consistent_entries() {
    fn check() {
        let routes = match list_routes() {
            Ok(routes) => routes,
            #[cfg(not(any(
                target_vendor = "apple",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "linux",
                target_os = "android",
                windows
            )))]
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return,
            Err(e) => panic!("failed to retrieve routing table: {e}"),
        };
        // A successful UDP connect requires a route but sends no packets.
        if std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.connect("127.0.0.1:9"))
            .is_ok()
        {
            assert!(routes.iter().any(|r| r.family == RouteFamily::Ipv4));
        }
        for route in routes {
            assert_eq!(route.family, RouteFamily::from(route.destination.addr));
            assert!(
                route.destination.prefix_len
                    <= if route.destination.addr.is_ipv4() {
                        32
                    } else {
                        128
                    }
            );
            if route.on_link {
                assert!(route.gateway.is_none());
            }
            assert_ne!(route.ifindex, Some(0));
        }
    }
    std::thread::scope(|s| {
        s.spawn(check);
        check();
    });
}

#[cfg(feature = "serde")]
#[test]
fn reads_legacy_json_and_round_trips_new_fields() {
    let json = r#"{
        "family":"Ipv4","destination":{"addr":"0.0.0.0","prefix_len":0},
        "gateway":"192.0.2.1","on_link":false,"ifindex":2,"ifname":"eth0",
        "metric":10,"flags":["Up","Gateway"],"protocol":"Static","scope":"Global",
        "table":254,"lifetime_ms":null
    }"#;
    let mut route: RouteEntry = serde_json::from_str(json).unwrap();
    assert_eq!(route.source, None);
    assert_eq!(route.next_hop_id, None);
    route.next_hop_weight = Some(256);
    let bytes = serde_json::to_vec(&route).unwrap();
    assert_eq!(serde_json::from_slice::<RouteEntry>(&bytes).unwrap(), route);
}
