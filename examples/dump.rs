fn main() {
    match netroute::list_routes() {
        Ok(routes) => {
            for route in routes {
                println!("family: {}", route.family);
                println!("dst: {}", route.destination);
                println!("gateway: {:?}", route.gateway);
                println!("on_link: {}", route.on_link);
                println!("ifindex: {:?}", route.ifindex);
                println!("ifname: {:?}", route.ifname);
                println!("metric: {:?}", route.metric);
                println!("flags: {:?}", route.flags);
                println!("proto: {:?}", route.protocol);
                println!("scope: {:?}", route.scope);
                println!("table: {:?}", route.table);
                println!("lifetime_ms: {:?}", route.lifetime_ms);
                println!("----------------------------------------");
            }
        }
        Err(e) => eprintln!("Error listing routes: {}", e),
    }
}
