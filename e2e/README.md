# End-to-end tests

`e2e` compiles the app's own `tunnel.rs`, `proxy.rs`, `vpn.rs` and `settings.rs` together with a test SSH server. The server accepts `test` / `secret` and logs every forwarded connection, so the tests can tell whether traffic really went through SSH.

```sh
cd e2e
cargo run -- tunnel        # SSH login, SOCKS4a/5 forwarding, host-key pinning, error messages
cargo run -- proxy         # set and restore the system proxy (macOS, Windows)
cargo run -- vpn full      # full VPN: approve the admin prompt; checks routes, DNS, traffic, restore
cargo run -- vpn cancel    # cancel the admin prompt; checks the error and that nothing changed
cargo run -- vpn crash     # approve, then abort; the helper must restore the network by itself
cargo run -- server [addr] # just the test SSH server (default 0.0.0.0:2222), e.g. for the Android emulator at 10.0.2.2
```

`vpn` and `proxy` change this machine's network settings while they run, and restore them afterwards. macOS keeps an approved admin prompt for a few minutes, so `vpn cancel` only shows a prompt once that has expired.

`vpn` needs administrator rights. Run it normally to get the OS prompt, or as root (`sudo`) to skip the prompt, which is how CI runs it on macOS and Linux. On Linux the test server pins its own outgoing connections to the physical interface (`SO_BINDTODEVICE`), so it doesn't loop back into the tunnel. Without root it can't do that, so start a separate server (`e2e server` in another network namespace or container) and point the test at it with `E2E_SERVER=ip:port`.
