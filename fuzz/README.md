# Fuzz targets

| Target | Code | Input |
|---|---|---|
| `decode` | `capture::decode` (SPEC.md 4) | first byte: link type, rest: the frame |
| `http` | `post::http::scan` (SPEC.md 13.2) | first byte: options, rest: a server-to-client flow |

The targets use [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
(libFuzzer), which needs a nightly Rust or a stable one with
`RUSTC_BOOTSTRAP=1`. Pick one of the two setups below.

## Setup

With rustup (no Nix):

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo build --release                 # for seed.py below
```

Then run the commands below as `cargo +nightly fuzz run decode ...`. A
nightly toolchain has the AddressSanitizer runtime, so `-s none` can be left
out.

With Nix (optional):

```sh
nix develop .#fuzz                    # cargo-fuzz, RUSTC_BOOTSTRAP=1
cargo build --release
```

nixpkgs' rustc has no AddressSanitizer runtime, so keep `-s none`. Panics,
hangs (`-timeout`) and large allocations are found without it.

## Running

```sh
python3 -I fuzz/seed.py target/release/tcpflow   # starting corpus from tests/captures
cd fuzz
cargo fuzz run -s none decode -- -max_total_time=900 -max_len=65536 -timeout=5
cargo fuzz run -s none http   -- -max_total_time=900 -max_len=65536 -timeout=5
```

A failing input is saved in `fuzz/artifacts/<target>/`. Replay it with
`cargo fuzz run -s none <target> <file>`, fix the bug, and add the input as a
regression test to `tests/`.
