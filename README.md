# tcpflow 2.0 (Rust rewrite, work in progress)

tcpflow captures data transmitted as part of TCP connections (flows) and
stores each flow in its own file, for protocol analysis and debugging.

This branch is a clean Rust implementation of tcpflow. It keeps what users
see (options, file names, file contents, console output and the DFXML
report) and fixes known 1.x bugs. The C++ tcpflow 1.x is on the `main`
branch.

- [SPEC.md](SPEC.md) specifies the behaviour, including the intentional
  differences from 1.6.2.
- `tests/scripts/conformance.py check <tcpflow>` compares a build against the
  golden output of tcpflow 1.6.2 in `tests/golden/`.

## Building

Needs Rust 1.87 or newer (for example from [rustup](https://rustup.rs)),
libpcap with its headers and pkg-config. On Debian or Ubuntu:
`apt install libpcap-dev pkg-config`; on Fedora: `dnf install libpcap-devel
pkgconf`; on macOS libpcap comes with the system. Python 3 is only needed
for the conformance check.

```
cargo build --release
cargo test
python3 tests/scripts/conformance.py check target/release/tcpflow
```

The binary is `target/release/tcpflow`.

Nix is optional: if you use it, `nix develop` gives a shell with all of the
above, and `nix build` builds the package.

## License

GPL-3.0, see [LICENSE](LICENSE).

## Citation

Passive TCP Reconstruction and Forensic Analysis with tcpflow, Simson
Garfinkel and Michael Shick, Naval Postgraduate School Technical Report
NPS-CS-13-003, September 2013. https://calhoun.nps.edu/handle/10945/36026
