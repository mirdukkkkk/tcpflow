# Fuzz targets

| Target | Code | Input |
|---|---|---|
| `decode` | `capture::decode` (SPEC.md 4) | first byte: link type, rest: the frame |
| `http` | `post::http::scan` (SPEC.md 13.2) | first byte: options, rest: a server-to-client flow |

The targets use the stable rustc of the flake with `RUSTC_BOOTSTRAP=1` and
no sanitizer (`-s none`): nixpkgs' rustc has no ASan runtime. Panics,
hangs (`-timeout`) and large allocations are found without one.

```sh
nix develop .#fuzz
python3 -I fuzz/seed.py target/release/tcpflow   # after cargo build --release
cd fuzz
cargo fuzz run -s none decode -- -max_total_time=900 -max_len=65536 -timeout=5
cargo fuzz run -s none http   -- -max_total_time=900 -max_len=65536 -timeout=5
```

A failing input is saved in `fuzz/artifacts/<target>/`. Replay it with
`cargo fuzz run -s none <target> <file>`, fix the bug, and add the input as a
regression test to `tests/`.
