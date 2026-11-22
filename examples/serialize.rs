use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let routes = netroute::list_routes()?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    serde_json::to_writer_pretty(&mut out, &routes)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
