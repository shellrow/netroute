[crates-badge]: https://img.shields.io/crates/v/netroute.svg
[crates-url]: https://crates.io/crates/netroute
[license-badge]: https://img.shields.io/crates/l/netroute.svg
[examples-url]: https://github.com/shellrow/netroute/tree/main/examples
[doc-url]: https://docs.rs/netroute/latest/netroute

# netroute [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform routing table enumerator

## Usage

Add `netroute` to your dependencies

```toml
[dependencies]
netroute = "0.4"
```

Enable the optional `serde` feature to serialize the collected routes:

```toml
netroute = { version = "0.4", features = ["serde"] }
```

For more details, see [examples][examples-url] or [doc][doc-url].  
