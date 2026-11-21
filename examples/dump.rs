fn main() -> std::io::Result<()> {
    for route in netroute::list_routes()? {
        println!("{route:#?}");
    }
    Ok(())
}
