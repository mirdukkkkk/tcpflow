# Tests

```sh
cargo test                                                       # unit and integration tests
python3 -I tests/scripts/conformance.py check target/release/tcpflow   # golden tests
sudo sh tests/scripts/privs-root.sh                              # -U, -z, -i as root
```

- `*.rs`: integration tests, one file per area (`cli`, `input`, `flow`, `post`,
  `split`, `unprocessed`, `hooks`, `semlock`, `live`). `common/` builds small
  captures in code for the cases no real capture covers.
- `captures/`: the capture files, grouped by what they exercise. See
  [captures/README.md](captures/README.md).
- `golden/`: the output of tcpflow 1.6.2 (with the `fix/*` branches) for every
  capture under every run of `scripts/conformance.py` (SPEC.md section 15).
  `golden/EXPECTED_DIFFERENCES` lists the cases where 2.0 differs on purpose.
- `scripts/`: `conformance.py` (golden tests), `make-wifi.py` (builds the
  802.11 captures) and `privs-root.sh` (root checks, run in CI).

`tests/live.rs` captures on the loopback device of a new network namespace
(`unshare -rn`); it is skipped where user namespaces are not available, except
in CI, which sets `TCPFLOW_REQUIRE_NAMESPACES=1`.
