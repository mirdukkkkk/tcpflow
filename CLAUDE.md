# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Branches

- `rust`: tcpflow 2.0, a clean Rust rewrite. The C++ code is removed here. `SPEC.md` is the specification; it is the source of truth for behaviour.
- `main`: tcpflow 1.x (C++, autotools). Fixes for 1.x bugs found during the rewrite live in `fix/*` branches off `main`, one bug per branch, each with a shell test in `tests/`.

## Build (rust)

Needs Rust (edition 2024, MSRV 1.87) and libpcap with pkg-config. With Nix: `nix develop` for a shell with cargo, clippy, libpcap and python3; `nix build` builds and tests the package; `nix flake check` also runs the conformance check. The 1.x flake is in `nix/tcpflow-1.x/`.

```sh
cargo build --release          # target/release/tcpflow
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                     # unit tests + tests/*.rs integration tests
                               # (tests/live.rs captures on lo in `unshare -rn`, skipped without user namespaces)
sudo sh tests/scripts/privs-root.sh   # -U/-z/-i as real root (CI job `root`)
python3 -I tests/scripts/conformance.py check target/release/tcpflow   # golden tests
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy and tests on Ubuntu and macOS, the conformance check and `tests/scripts/privs-root.sh` (as root) on Ubuntu. On Ubuntu the live tests must not be skipped (`TCPFLOW_REQUIRE_NAMESPACES=1`). Conformance is blocking: every case must match.

## Conformance tests

- `tests/scripts/conformance.py` runs every capture under `tests/captures/` under each run in `RUNS` (`default`, `all`, `index`, `bins`, `template`, `limit`, `pcap`, `unprocessed`, `console`, `console-hdr`, `hex`, `json`) and compares with `tests/golden/` (SPEC.md section 15).
- The golden data comes from a reference 1.6.2 binary: `main` plus all `fix/*` branches merged. `conformance.py generate <ref>` refuses to write golden data if the reference hangs or crashes.
- When 2.0 differs from the golden data, find out which side is wrong. If 1.x is wrong: add a `D<n>` row to SPEC.md section 17, fix 1.x in a new `fix/*` branch with a test if it is cheap, rebuild the reference with that branch merged, and regenerate the golden data. Otherwise record the case in `tests/golden/EXPECTED_DIFFERENCES`.
- Building the reference: a detached worktree of the latest `ref: merge ...` commit, merge the new `fix/*` branch (conflicts in `tests/Makefile.am` are unions of the `SH_TESTS`/`EXTRA_DIST` lists), copy in `nix/tcpflow-1.x/flake.nix` and its `flake.lock`, `nix build path:.#tcpflow` (runs `make check`). Tag the new `ref: merge` commit `ref-<n+1>` and push the tag, so the reference stays reachable.

## Architecture (rust)

Packet path: `capture::input` (capture files with decompression, or a live device) → `main::read_packets` → an `Engine` (`flow::demux::Demux` for reassembly or `output::split::Splitter` for `-K`) → files, report, post-processors. Unprocessed frames go to `-w`.

- `main.rs`: the run: outputs, privilege drop, input loop. `cli.rs`: option parsing into `Config`. `log.rs`: stderr messages and the `-d` level.
- `capture/`: `input` opens files and devices; `decode` handles link layers, IPv4/IPv6 (with extension headers) and TCP; `wifi` handles 802.11 behind radiotap or Prism (test captures from `tests/scripts/make-wifi.py`). `Decoded::UnprocessedIp` is what `-w` writes; `Decoded::Other` means the link layer does not carry IP.
- `flow/`: `demux` is the flow table, LRU open-file limit, closing and the retransmission check against closed flows; `stream` is a flow file as a byte array at stream offsets; `naming` is the `-T`/`-F` templates and the connection counter.
- `output/`: `console` (`-c`/`-C`/`-D`/`-g`/`-J`), `report` (`report.xml`, DFXML), `split` (`-K`), `pcapfile` (pcap writing for `-K` and `-w`), `hooks` (`tcp_cmd`/`http_cmd`, at most 10 each and waited for at exit, and `tcp_alert_fd`/`http_alert_fd`, called from `demux` when a flow file is created and closed).
- `post/`: post-processing (`-a`, `-e`) of closed flows: MD5 in `mod.rs`, HTTP body extraction in `http`, decompression and content types in `mime`.
- `sys/`: everything that depends on the operating system, so that the other modules use no `libc` and no `unsafe` (except handing descriptors to libpcap in `capture::input` and `output::pcapfile`): `privs` (`-U`/`-z`: created outputs are handed over by descriptor with `fchown`, groups, chroot, setgid, setuid, once the first input is open; SPEC.md 16), `signals` (SIGINT/SIGTERM/SIGHUP stop the read loop, D12; a live capture is woken with `pcap::BreakLoop`), `files` (output files with `O_NOFOLLOW`, D36), `limits` (`getrlimit`, `getrusage`), `semlock` (`-L`), `fd` (caller descriptors for the alerts), `command` (`sh -c` for the hooks). A port to another OS would replace these modules.

`capture` depends on nothing else. `flow::demux` calls `output` (console, hooks, semlock) and `post` when it prints and closes flows, and `output` uses the flow types. `log` and `sys` are used anywhere.

## Conventions

- Every behaviour has a SPEC.md section; code comments cite it (`SPEC.md 12`, `D20`). Keep comments short and only where they explain something non-obvious.
- 1.x commit messages are short imperative sentences ("Fix -w aborting on pcapng ..."), as is the `rust` branch history.
- Security: `SECURITY.md` asks for a PoC, a test that fails before the fix, and the fix.
