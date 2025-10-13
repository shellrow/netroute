fn main() {
    match netroute::list_routes() {
        Ok(routes) => match serde_json::to_string_pretty(&routes) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("Error serializing routes to JSON: {}", e),
        },
        Err(e) => eprintln!("Error listing routes: {}", e),
    }
}
