[crates-badge]: https://img.shields.io/crates/v/netroute.svg
[crates-url]: https://crates.io/crates/netroute
[license-badge]: https://img.shields.io/crates/l/netroute.svg
[examples-url]: https://github.com/shellrow/netroute/tree/main/examples
[doc-url]: https://docs.rs/netroute/latest/netroute

# netroute [![Crates.io][crates-badge]][crates-url] ![License][license-badge]

Read IPv4 and IPv6 routes from the operating system's routing tables. netroute uses routing netlink on Linux and Android, IP Helper on Windows, and routing sysctl on Apple platforms, FreeBSD, NetBSD, and OpenBSD.

## Install

```sh
cargo add netroute
```

or 

```toml
[dependencies]
netroute = "0.4"
```

## Usage

```rust
fn main() -> std::io::Result<()> {
    for route in netroute::list_routes()? {
        println!("{} via {:?} on {:?}", route.destination, route.gateway, route.ifname);
    }
    Ok(())
}
```

Each entry includes the destination prefix and available next-hop, interface, and routing metadata. Linux inline multipath routes produce one entry per next hop. An entry without a gateway can also represent a discard route. Use `on_link` to identify direct routes.

The optional `serde` feature enables serialization and deserialization of route entries. To print the local routing table as JSON from this repository, run `cargo run --example serialize --features serde`.

The minimum supported Rust version is 1.85. Route visibility depends on the process's network context and OS permissions, particularly on mobile platforms.

See [examples][examples-url] and [API docs][doc-url] for more details.
