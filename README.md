# tcpflow 2.0

tcpflow captures data transmitted as part of TCP connections (flows) and
stores it in a way that is convenient for protocol analysis and debugging.
Each TCP flow is stored in its own file, so a typical connection gives two
files, one for each direction. tcpflow reads packets from a network
interface or from stored capture files (pcap or pcapng, also compressed).

tcpflow is similar to tcpdump in that both process packets from the wire
or from a file. The difference is that tcpflow reconstructs the actual data
streams: it understands sequence numbers and puts the data together
correctly regardless of retransmissions or out-of-order delivery.

tcpflow 2.0 is a rewrite of tcpflow in Rust. It keeps what users see:
options, file names, file contents, console output and the DFXML report.
It fixes known bugs of 1.x and drops parts that were rarely used. The C++
tcpflow 1.x is on the `main` branch.

## What use is it?

tcpflow is a tool for understanding network traffic and for network
forensics. Unlike programs such as Wireshark, which show many packets or a
single TCP connection, tcpflow can show hundreds of thousands of TCP
connections in context.

A common use is to reveal the contents of HTTP sessions: tcpflow can
reconstruct web pages downloaded over HTTP, and extract files delivered
over it, such as malware from drive-by downloads. It is also used to
reverse engineer undocumented protocols, which is what Jeremy Elson
originally wrote it for.

## Installing

Most GNU/Linux distributions and Homebrew ship tcpflow 1.x
(`apt install tcpflow`, `dnf install tcpflow`, `brew install tcpflow`).
tcpflow 2.0 is built from source for now.

### Building from source

Needs Rust 1.87 or newer (for example from [rustup](https://rustup.rs)),
libpcap with its headers, and pkg-config:

| System | Command |
|---|---|
| Debian, Ubuntu | `apt install libpcap-dev pkg-config` |
| Fedora | `dnf install libpcap-devel pkgconf` |
| macOS | nothing: libpcap comes with the system |
| FreeBSD, OpenBSD | nothing: libpcap is in the base system |

Then:

```sh
git clone https://github.com/simsong/tcpflow.git
cd tcpflow
git switch rust
cargo build --release
```

The program is `target/release/tcpflow`; copy it anywhere on your `PATH`.
Capturing from an interface needs root, or on Linux the capabilities
`cap_net_raw,cap_net_admin`.

Shell completions are in `doc/completions/`. To install them for your user:

| Shell | Command |
|---|---|
| bash | `cp doc/completions/tcpflow.bash ~/.local/share/bash-completion/completions/tcpflow` |
| zsh | `cp doc/completions/_tcpflow ~/.zfunc/`, with `fpath=(~/.zfunc $fpath)` before `compinit` in `~/.zshrc` |
| fish | `cp doc/completions/tcpflow.fish ~/.config/fish/completions/` |

Nix is optional: if you use it, `nix build` builds the package and
`nix develop` gives a shell with all of the above.

## Using it

```sh
tcpflow -r capture.pcap                      # one file per flow in the current directory
tcpflow -o out -r capture.pcap.gz 'port 80'  # into out/, only port 80 (a libpcap filter)
sudo tcpflow -i eth0 -c                      # live: print flows to the terminal
sudo tcpflow -i eth0 -o out -U nobody        # live: drop root after opening the interface
tcpflow -a -o out -r capture.pcap            # also extract HTTP bodies, add MD5 to the report
tcpflow -K -o out -r capture.pcap            # one pcap file per flow instead of the data
```

`tcpflow -h` lists the options, `tcpflow -hh` also the parameters (`-S`)
and the file name codes (`-T`). [SPEC.md](SPEC.md) describes every option in
detail.

### Output file names

By default a flow file is named

    sourceip.sourceport-destip.destport[--VLAN][cNNNN]

with addresses and ports padded with zeros, for example

    192.168.001.103.36322-171.025.221.158.00080

is the data sent from 192.168.1.103 port 36322 to 171.25.221.158 port 80.
`--VLAN` is added for packets with a VLAN tag; `cNNNN` counts connections
that would otherwise get the same name. `-Ft` puts the Unix start time in
front (`1510959430T192.168...`), and `-T` sets any template, for example
`-T '%T--%A-%B'` gives `2017-11-17T22:57:10Z--192.168.001.103-171.025.221.158`.
A `/` in a template creates directories.

### HTTP bodies

With `-a` or `-e http`, each response body in a server-to-client flow is
written next to the flow file, decompressed if it was sent with gzip or
deflate (`-Z` keeps it compressed):

    171.025.221.158.00080-192.168.001.103.36322-HTTPBODY-001.html

The extension comes from the `Content-Type`.

### The report

tcpflow writes `report.xml` (DFXML) into the output directory: how it was
run, and for every flow the addresses, ports, byte and packet counts, the
file name and, with `-a` or `-FM`, the MD5 of the data.

## Differences from tcpflow 1.x

The [differences table in SPEC.md](SPEC.md#17-intentional-differences-from-162)
lists every intentional change. The main ones:

- many 1.x bugs are fixed: hangs with `-Fc` and `%%c`, wrong data after
  a sequence shift, `-L`, `-FM` and `-w` that did not work, `-K` files with
  the wrong link type, 802.11 and BSD loopback captures that gave no flows;
- compressed HTTP bodies are limited in size (`-S http_max_body`);
- `tcp_cmd` and `http_cmd` get the file name as an argument, never parsed by
  the shell;
- dropping privileges (`-U`, `-z`) fails safely, and flow files are never
  written through symbolic links;
- no netviz (`report.pdf`), no SQLite output, no scan_python, no Windows build.

## Limitations

- IP fragments are not reassembled: flows with fragmented packets are not
  stored correctly. Fragmentation is rare in practice.
- Linux, macOS and the BSDs are supported; Windows is not.

Please report bugs on the
[GitHub issue tracker](https://github.com/simsong/tcpflow/issues).
Security problems: see [SECURITY.md](SECURITY.md).

## Development

```sh
cargo test                                                        # unit and integration tests
python3 tests/scripts/conformance.py check target/release/tcpflow # against the 1.6.2 output
```

[tests/README.md](tests/README.md) describes the tests and test captures,
[fuzz/README.md](fuzz/README.md) the fuzz targets.

## Citation

If you are writing an article about tcpflow, please cite:

Passive TCP Reconstruction and Forensic Analysis with tcpflow, Simson
Garfinkel and Michael Shick, Naval Postgraduate School Technical Report
NPS-CS-13-003, September 2013. https://calhoun.nps.edu/handle/10945/36026

## Authors

tcpflow was written by Jeremy Elson and is maintained by Simson L.
Garfinkel <simsong@acm.org>. tcpflow 2.0 is a rewrite by
mirdukkkkk.

Thanks to:

- Jeffrey Pang, for the radiotap implementation;
- Doug Madory, for the original Wi-Fi parser;
- Johnny Tevessen, for Linux systems still using libc5;
- Ross Golder, for a spec file for generating tcpflow RPMs;
- Jose M. Alcaide, for the patch for the `-r` option;
- olibre, for encouragement, many patches and the CMake build.

## License

GPL-3.0, see [LICENSE](LICENSE).
