use netroute::{RouteFamily, list_routes};

#[test]
fn route_retrieval() {
    let routes = list_routes().expect("failed to retrieve routing table from OS");
    assert!(
        !routes.is_empty(),
        "routing table retrieval succeeded but returned no routes"
    );

    for route in &routes {
        match route.family {
            RouteFamily::Ipv4 => assert!(
                route.destination.prefix_len <= 32,
                "invalid IPv4 prefix length: {}",
                route.destination.prefix_len
            ),
            RouteFamily::Ipv6 => assert!(
                route.destination.prefix_len <= 128,
                "invalid IPv6 prefix length: {}",
                route.destination.prefix_len
            ),
        }
    }
}
