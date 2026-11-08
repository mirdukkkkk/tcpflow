# Changelog

The `D` numbers refer to the table of intentional differences in
[SPEC.md, section 17](SPEC.md#17-intentional-differences-from-162), which
describes each change in detail. The history of 1.x before this file is in
`NEWS` and `ChangeLog` on the `main` branch.

## 2.0.0 (unreleased)

tcpflow rewritten in Rust. Options, file names, file contents, console
output and the DFXML report stay as in 1.6.2; a conformance test compares
both on every test capture. Bugs of 1.x are fixed rather than reproduced.
Fixes for several of them were also proposed for 1.x, in pull requests #286
to #296.

### Security

- Compressed inputs (`.gz`, `.bz2`, `.xz`, `.lzma`, `.zip`) are
  decompressed in-process; 1.x ran a shell command with the file name in
  it, so a name containing `'` could run commands (D6).
- `tcp_cmd` and `http_cmd` get the file name as an argument, never parsed
  by the shell (D7).
- Files in the output directory are never opened through symbolic links,
  and new flow files are created exclusively (D36).
- Dropping privileges with `-U` and `-z`: outputs are handed to the new
  user by descriptor, never by path, and only if tcpflow created them; a
  numeric uid without a passwd entry needs an explicit group; `-o` is
  inside the chroot; any failure is fatal (D22 to D25, based on #281).
- HTTP bodies are decompressed up to `-S http_max_body`, 1 GiB by default,
  so a small compressed response cannot fill the disk (D38).
- Malformed packets are checked before they are read: a TCP data offset
  below 5 (D41), short segments with `-K`, and Linux cooked frames that are
  not IP (D42).

### Fixed

- Hangs: `-Fc` when two flows get the same name (D11), a literal `%%c` in
  `-T` (D43). SIGINT, SIGTERM and SIGHUP stop processing promptly and the
  report is still written (D12).
- `tcp_cmd` and `http_cmd` no longer corrupt the reading of the input file
  (D31); tcpflow waits for running commands before it exits (D33).
- Stream reassembly: data that arrives before the guessed start of the
  stream is shifted correctly (D37); with `-c`, `-C` and `-FX` long flows
  and FINs work as with files (D39).
- `-L` works (D34), `-FM` writes MD5 digests (D17), and every flow is
  post-processed, also flows identical to an earlier one (D18).
- `-w` works with pcapng, big-endian and compressed inputs (D20) and with
  live capture (D26).
- `-K`: files have the link type of the input instead of Token Ring (D19),
  flows with the same name share a file (D40), and the open file limit
  applies (D3).
- `.findx` offsets are correct after a shift, and the index is sorted
  (D16).
- Decoding: plain 802.11 captures (D29, D30), IPv6 loopback captures from
  macOS and the BSDs (D10), IPv6 extension headers (D28), IPv6 packets with
  payload length 0 (D14), the VLAN ID without the priority bits (D1).
- `report.xml`: a valid structure (D2), MAC addresses only for Ethernet
  (D13), always 6 digits of microseconds (D15).
- `-J` takes addresses and ports from the flow, not the file name, so IPv6
  and custom templates work (D4).
- `tcp_alert_fd` writes `open` once per flow file (D32).

### Changed

- `-J` alone implies `-c` (D21).
- `-i` together with `-r` or `-R` is an error (D27).
- `-V` exits with status 0 (D5).
- "SYN TO IGNORE!" and file time errors are printed only at higher debug
  levels (D8, D9).
- Flows that expire at the same time with `tcp_timeout` are closed oldest
  first.
- Much faster with many open flows: `tcp_timeout`, the open file limit and
  `-K` no longer scan all flows for every packet (50,000 flows: 18 s to
  1.3 s).

### Added

- `-S http_max_body`.
- A man page, written in Markdown (`doc/tcpflow.1.md`), and shell
  completions for bash, zsh and fish (`doc/completions/`).
- Fuzz targets for packet decoding and HTTP body extraction (`fuzz/`).

### Removed

- netviz: the one-page PDF summary `report.pdf` (D35). `-e netviz` is
  still accepted and does nothing.
- The SQLite flow database, Windows builds, and the autotools and CMake
  builds; tcpflow is built with `cargo`.

## 1.6.2 (not released yet)

To be written when 1.6.2 is released.

## 1.6.1 (2021-02-18)

- Hotfixes for 1.6.0 (#230, #234).

## 1.6.0 (2020)

- `-K`: one pcap file per flow.
- `-S tcp_cmd` runs a command for each closed flow file, `-S tcp_alert_fd`
  reports flow files as they are opened and closed (#211).
- `%S`: the session ID in file names (#212).
- HTTP bodies larger than 2 GB (#223).
- Fixed a crash on interrupt (#225), out-of-bounds reads (#221), a crash
  as a non-root user (#203), a crash when `futimes()` fails.
- The Python post-processor was removed (#214).

## 1.5.2 (2018-11-21), 1.5.1 (2018-11-12)

- `-J`: console output as JSON lines (#185).
- `-S packet-buffer-timeout` for live capture (#191).
- `-0` no longer takes an argument (#188).
- Fixed a possible stack overflow (#195), the FreeBSD build with GCC
  (#196).

## 1.5.0 (2018-08-19)

- `-U` and `-z`: drop root privileges and chroot; libcap support.
- Long options (`--help`, `--version`, `--verbose`).
- A Python post-processor.
- A CMake build and setup scripts for Fedora, Ubuntu and Arch Linux.
- Fixed a buffer overflow, an invalid `report.xml` for truncated captures,
  and the shutdown of tcpflow.

## 1.4.0 (2013-08-03) to 1.4.5 (2015-08-24)

- A rewritten TCP implementation: flows larger than 4 GiB; packets sent
  after a connection was closed are compared with it and dropped as
  retransmissions, or stored in a new file.
- A rewritten HTTP parser that handles several responses per connection.
- `-S http_cmd`, `-S tcp_timeout`, `-S http_alert_fd`.
- `-D` hex dump; `-g` coloured console output (it was `-e` in 1.3 and `-J`
  in 1.4.0 to 1.4.4); `-0` (1.4.5).
- `-S enable_report=NO`.
- A `%c` is appended to a `-T` template that has none.
- RFC 1122 keepalive packets are handled.
- netviz: the one-page PDF report.

## 1.3.0 (2012-08-21)

- Builds with mingw32 and mingw64 for Windows.
- DFXML fixes, better autoconf support.

## 1.2.7 (2012-05-26)

- `-r` may be repeated.
- `-R`: read a file only to finish flows that are already open, for series
  of captures.

## 1.2.0 (2012-03-15)

- Post-processing of closed flows: `-FM` computes the MD5 of every flow,
  and HTTP responses are split into headers and body.

## 1.1.0 (2012-01-19)

- The code base moved to C++, with a hash table that scales better.
- Old connections expire, so memory use no longer grows without bound.
- Several connections with the same addresses and ports are stored in
  different files, with `c0001`, `c0002` appended.
- File names may start with the ISO 8601 or Unix start time.
- A DFXML report with every flow.

## 1.0.x (2011)

- Simson L. Garfinkel took over maintenance.
- IPv6 support.
- The VLAN in file names is written as `--42` instead of `[42]`.

## 0.21 (2003-08-07)

- Fixed a format string vulnerability, found by David Goldsmith.
- Linux cooked capture and ISDN, by Detlef Conradin.

## 0.20 (2001-02-26)

- tcpflow reads tcpdump capture files (`-r`), a patch by Jose M. Alcaide.
- SIGTERM, SIGINT and SIGHUP are caught, so libpcap can reset the
  interface.

## 0.12 (1999-04-20), 0.11 (1999-04-13)

- Portability fixes, Linux libc5 support (Johnny Tevessen), usage help.

## First release (1999-04-12)

- First public release, by Jeremy Elson.
