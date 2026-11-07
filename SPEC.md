# tcpflow 2.0 specification

This document specifies the behaviour of tcpflow 2.0, a clean Rust
implementation. It is derived from the tcpflow 1.6.2 C++ sources, the
1.6.2 man page and the observed behaviour of the 1.6.2 binary. Where the
man page and the code disagree, the code wins. Where 1.6.2 behaviour is a
bug, this document says so and specifies the fix (see
[Intentional differences](#14-intentional-differences-from-162)).

The reference binary is tcpflow 1.6.2 with the fixes from PRs #281–#285
and the `-K` bounds fix applied.

## 1. Compatibility levels

Every output is in one of three levels. The conformance tests
(section 15) enforce levels A and B.

- **A, byte-identical:** must match the reference output byte for byte:
  - flow file names and contents;
  - HTTP body file names and contents;
  - `.findx` index files;
  - per-flow pcap files (`-K`) and the unprocessed-packet pcap (`-w`);
  - console output (`-c`, `-C`, `-D`, `-s`, `-0`, `-g`);
  - modification times of flow files.
- **B, semantically equal:** the same information, but formatting may
  differ. This covers the per-flow `<fileobject>` entries of `report.xml`
  and the exit status.
- **C, free:** may differ without restriction:
  - diagnostics on stderr, including debug output (`-d`);
  - the environment, rusage and summary parts of `report.xml`;
  - the `report.pdf` rendering;
  - `--help` text.

## 2. Command line

```
tcpflow [options] [expression]
```

`expression` is a libpcap filter expression (pcap-filter(7)). All
remaining arguments are joined with single spaces. With `-l` they are
input files instead.

Phase marks the order of implementation: **1** is the first release
(MVP), **2** and **3** follow, **–** means the option is not carried over.

| Option | Meaning | Phase |
|---|---|---|
| `-r file` | Read packets from a capture file. Repeatable. `-` is stdin. | 1 |
| `-R file` | Read a capture file, but only to finish flows that are already open. Processed after all `-r` files. Repeatable. | 1 |
| `-l` | Treat non-option arguments as `-r` files instead of an expression. | 1 |
| `-i iface` | Live capture on `iface`. Without `-i`, `-r`, `-R` or `-l`, capture on the first device libpcap reports. | 2 |
| `-p` | Do not put the interface in promiscuous mode. | 2 |
| `-o dir` | Output directory, default `.`. Created (one level) if missing. | 1 |
| `-T template` | Flow file name template (section 7). If it has no `%c`, `%C%c` is appended. | 1 |
| `-F flags` | Filename and output flags (section 7.2). | 1 |
| `-b n` | Store at most `n` bytes per flow (section 6.4). | 1 |
| `-m n` | Sequence gap that starts a new flow (section 5.3). Default 16 MiB (16777216). | 1 |
| `-f n` | Maximum number of open flow files (section 8). | 1 |
| `-X file` | Write the DFXML report to `file`. Default `<outdir>/report.xml`. | 1 |
| `-c` | Console output only: print flow data to stdout, create no files and no report (section 9). | 1 |
| `-C` | Like `-c`, but without the flow name header. Does not disable the report. | 1 |
| `-D` | Console output as hex dump. Implies `-B`. | 1 |
| `-s` | Replace non-printable bytes with `.` in console output. | 1 |
| `-B` | Binary console output, cancels `-s`. | 1 |
| `-0` | No newline after each console packet. | 1 |
| `-g` | Color console output by direction. | 1 |
| `-J` | Console output as JSON lines (section 9.3). | 2 |
| `-I` | Write a `.findx` packet index next to each flow file (section 10). | 1 |
| `-K` | Write one pcap file per flow instead of reassembled data (section 11). | 2 |
| `-w file` | Write IP packets that were not processed as TCP to a pcap file (section 12). | 2 |
| `-a` | Enable all post-processing: HTTP and MD5. | 2 |
| `-e name` | Enable a post-processor: `http`, `md5`, `netviz`. | 2 |
| `-x name` | Disable a post-processor. | 2 |
| `-E name` | Disable all post-processors, then enable `name`. | 2 |
| `-Z` | Do not decompress gzip or deflate HTTP bodies. | 2 |
| `-S name=value` | Set a parameter (section 13). | 1 |
| `-U spec`, `--relinquish-privileges=spec` | Drop root privileges after opening the first input (section 16). | 2 |
| `-z dir`, `--chroot=dir` | chroot to `dir` when dropping privileges. Requires `-U` with a non-root user. | 2 |
| `-q` | Quiet: suppress the "too many files" warning. | 1 |
| `-d n` | Debug level. | 1 |
| `-v`, `--verbose` | Same as `-d 10`. | 1 |
| `-V`, `--version` | Print `TCPFLOW <version>` and exit with status 0. | 1 |
| `-h`, `--help` | Print usage and exit with status 0. `-hh` prints more. | 1 |
| `-L name` | Serialise console output across processes with a named semaphore. | 3 |
| `-H` | Print post-processor details. Replaced by `--help`. | – |
| `-A` | Deprecated since 1.5. | – |
| `-e python` | Removed in 1.6.0 (#214). | – |

Invalid options print usage to stderr and exit with status 1.

## 3. Input

- Capture files are read through libpcap. Both pcap and pcapng are
  accepted.
- Files ending in `.gz`, `.bz2`, `.xz`, `.lzma` or `.zip` are
  decompressed in-process. A `.zip` file is read as its first entry.
  No external program and no shell is used.
- The filter expression is compiled once per input with optimisation
  on. Packets that do not match are ignored.
- For each `-r` file in order, new flows may be created. For each `-R`
  file afterwards, only packets of flows that are still open are
  processed, and no new flows are created.
- An input that cannot be opened is a fatal error (exit status 1). A
  read error in the middle of a file is reported, processing continues
  with the next file, and the final exit status is 1.

## 4. Packet decoding

### 4.1 Link layers

| DLT | Handling |
|---|---|
| `EN10MB` (1), `IEEE802` (6) | Ethernet. Any number of 802.1Q (0x8100), 802.1ad (0x88a8) and 0x9100 tags are skipped. The VLAN ID of the outermost tag is recorded (section 14, D1). EtherType 0x0800 and 0x86dd are decoded; others are ignored. |
| `NULL` (0) | 4-byte address family header in the capturing host's byte order. IPv4 is family 2; IPv6 is 10, 24, 28 or 30 (Linux, the BSDs, macOS). Both byte orders are accepted (D10). Other families are ignored. |
| `LOOP` (12 on OpenBSD, 108) | 4-byte header skipped; the IP version nibble selects IPv4 or IPv6. |
| `RAW` (12, 14, 101) | IP directly. The version nibble selects IPv4 or IPv6. |
| `PPP` (9) | 4-byte header skipped. |
| `PPP_ETHER` (51) | PPPoE: 6-byte PPPoE header and 2-byte PPP protocol skipped. |
| `LINUX_SLL` (113) | 16-byte cooked header; protocol field selects IPv4 or IPv6. |
| `IEEE802_11` (105), `IEEE802_11_RADIO` (127), `PRISM_HEADER` (119) | 802.11 data frames with LLC/SNAP. Phase 3. |

An unsupported link type is a fatal error: `unknown datalink type N`.

### 4.2 IPv4

A packet is ignored ("not processed") when any of these is true:

- fewer than 20 bytes are captured after the link header;
- the protocol is not TCP (6);
- the fragment offset is non-zero (fragments are not reassembled);
- the header length (IHL × 4) is less than 20, or larger than the IP
  total length, or larger than the captured bytes.

The IP total length `ip_len` is trusted with two exceptions:

- if `ip_len` is 0, the captured length is used. This is TCP segmentation
  offload on the capturing host (#197);
- the payload is always clamped to the captured bytes.

### 4.3 IPv6

The packet is ignored when fewer than 40 bytes are captured or the next
header is not TCP. Extension headers are not followed (phase 3). The
payload length is clamped to the captured bytes. A payload length of 0
uses the captured length, as for IPv4.

### 4.4 TCP

- With fewer than 20 bytes of TCP header, the segment is ignored. In `-K`
  mode only the 4 bytes of the ports are needed (section 11).
- The data offset (`th_off` × 4) is the header length. If it is larger
  than the segment, the segment has no data.
- Flags used: SYN, ACK, FIN, RST.

## 5. Flows

### 5.1 Identity

A flow is one direction of a TCP connection. Its key is (address family,
source address, destination address, source port, destination port). The
two directions of a connection are two flows.

Each flow has:

- a **flow number**: a counter starting at 0, incremented for each new
  flow, used by `%N %K %M %G`;
- a **session ID**: the reverse flow's session ID if the reverse flow is
  open, otherwise a new counter value starting at 0, used by `%S`;
- the **start time** (first packet) and **last time** (latest packet);
- the source and destination MAC addresses of the first packet, if the
  link layer is Ethernet;
- the VLAN ID of the first packet, if any;
- counters: packets, total original length (`len`), total captured length
  (`caplen`), out-of-order events and protocol violations.

### 5.2 Creation

For a packet whose flow is not open:

1. During `-R` processing, the packet is ignored.
2. With no data, the packet creates a flow only if SYN is set.
3. With data, if a recently closed flow with the same key (section 5.5)
   already holds identical bytes at the packet's offset, the packet is a
   retransmission and is ignored.
4. Otherwise a flow is created. The initial sequence number (ISN) is
   `seq` if SYN is set, else `seq - 1`. The next expected sequence number
   is ISN + 1.

### 5.3 Sequence gaps

For a packet of an open flow, `delta = seq - next_expected` as a signed
32-bit value. If `|delta| > max_seek` (`-m`), the flow is closed
(section 5.4) and the packet starts a new flow under the rules of 5.2,
with the next free connection counter.

A SYN on an open flow that has already stored data is ignored.

### 5.4 Closing

A flow is closed when:

- an RST is seen (after storing any data in the same segment);
- a FIN has been seen and every byte up to the FIN has been stored. The
  stream size is `seq + datalen - ISN - 1` from the first FIN;
- its last packet is older than `tcp_timeout` seconds, if that parameter
  is set (section 13), checked against each new packet's timestamp;
- input ends: all open flows are closed in an unspecified order.

Closing a flow:

1. runs the post-processors on the flow file (section 13);
2. sets the flow file's access and modification time to the flow start
   time (microsecond precision);
3. writes its `<fileobject>` to the report.

### 5.5 Recently closed flows

The key, file name and ISN of the last 100 closed flows are kept for the
duplicate check in 5.2.3.

## 6. Stream reconstruction

The flow file is a byte array. The byte with sequence number `ISN + 1 + k`
is stored at offset `k`.

### 6.1 Placement

Each segment's data is written at its offset. Gaps that are never filled
remain zero bytes, and the file is extended as needed. Overlapping data
overwrites earlier data (last writer wins).

### 6.2 Data before the ISN

If a segment's offset is negative:

- if a SYN was seen on the flow, the segment is a violation: it is
  counted and ignored;
- otherwise the ISN was guessed wrong. The file content is shifted right
  by the missing bytes, the ISN moves back by the same amount, and the
  segment is written at offset 0. This counts as one out-of-order event.

### 6.3 Keepalives

A segment of exactly 1 byte at offset `next_expected - 1` is an RFC 1122
keepalive and is ignored.

### 6.4 Byte limit

With `-b n`, data at offsets ≥ `n` is not written. A segment that crosses
`n` is truncated. The flow's logical size still advances.

### 6.5 Out of order

A segment written at an offset lower than the current end of the
contiguous stream counts as an out-of-order event.

## 7. Flow file names

### 7.1 Template

The default template is `%A.%a-%B.%b%V%v%C%c`. The name is
`<outdir>/<expanded template>`, without the `<outdir>/` prefix when the
output directory is `.` or empty.

| Code | Expansion |
|---|---|
| `%A` / `%B` | Source / destination address. IPv4: four zero-padded decimal octets (`010.000.000.001`). IPv6: RFC 5952 text form (`2001:db8::1`). |
| `%a` / `%b` | Source / destination port, 5 digits, zero-padded. |
| `%E` / `%e` | Source / destination MAC, `xx:xx:xx:xx:xx:xx`, lowercase. All zeros if not Ethernet. |
| `%V` | `--` if the flow has a VLAN ID, else nothing. |
| `%v` | The VLAN ID in decimal if present, else nothing. |
| `%T` | Flow start time, ISO 8601 UTC, `YYYY-MM-DDTHH:MM:SSZ`. |
| `%t` | Flow start time, Unix seconds. |
| `%c` | The connection counter if it is > 0, else nothing. |
| `%C` | `c` if the connection counter is > 0, else nothing. |
| `%#` | The connection counter, always. |
| `%N` | flow number mod 1000, 3 digits. |
| `%K` | (flow number / 1000) mod 1000, 3 digits. |
| `%M` | (flow number / 10⁶) mod 1000, 3 digits. |
| `%G` | (flow number / 10⁹) mod 1000, 3 digits. |
| `%S` | Session ID, 20 digits, zero-padded. |
| `%%` | `%`. |

A `%` at the end of the template or followed by any other character is a
fatal error. Each `/` in the expanded name creates a directory level.

### 7.2 `-F` flags

The flags are applied in the order given and edit the current template:

| Flag | Effect |
|---|---|
| `c` | Always append the connection counter: `%C%c` becomes `c%#`, and any other `%c` becomes `%#`. The first file of a flow gets `c0` (D11). |
| `t` | Prepend `%tT`. |
| `T` | Prepend `%T`. |
| `k` | Prepend `%K/`. |
| `m` | Prepend `%M000-%M999/%M%K/`. |
| `g` | Prepend `%G000000-%G999999/%G%M000-%G%M999/%G%M%K/`. |
| `X` | Store no flow files. The report is still written. |
| `M` | Add an MD5 digest of every flow to the report. |

Any other character prints a warning and is ignored. Because `-T`
replaces the whole template, flags given before `-T` are lost.

### 7.3 Connection counter

A new flow file is created with exclusive create. The counter starts at
0, and while the name exists the counter is increased by one. As a
result, running tcpflow twice into the same directory creates `…c1`
files instead of overwriting.

## 8. Open file limit

At most `-f n` flow files are open at once. The default is the process
file limit minus 6. With `-I` each flow uses two descriptors, so the limit
is halved. When the limit is reached, or `open` fails with EMFILE or
ENFILE, the least recently written flow file is closed and reopened later
at its stored position.

## 9. Console output

With `-c` or `-C`, segments are printed in arrival order. No
reassembly is done.

### 9.1 Text

For each segment with data:

1. if `-g`, the color: `ESC[0;34m` for a flow whose first SYN had no ACK
   (client to server), else `ESC[0;31m`;
2. unless `-C` or `-J`: the flow name (section 7, counter 0, without
   `<outdir>`), then `: `, then a newline if `-D`;
3. the data:
   - raw bytes by default;
   - with `-s`, each byte that is not printable ASCII (0x20–0x7e), `\n` or
     `\r` is replaced by `.`;
   - with `-D`, a hex dump (9.2);
4. if `-g`, `ESC[0m`;
5. unless `-0`, a newline.

`-b n` limits the bytes printed per flow.

### 9.2 Hex dump

32 bytes per line: `%04x: ` offset, then the bytes as lowercase hex in
groups of two bytes separated by spaces, padded with spaces to the width
of the widest line so far, one space, then the bytes as ASCII with
non-printable bytes shown as `.`, then a newline.

### 9.3 JSON (`-J`)

One JSON object per segment, followed by a newline unless `-0`:

```json
{"src_host":"192.168.1.102","src_port":50955,"dst_host":"74.125.19.104","dst_port":80,"payload":[71,69,84]}
```

Addresses use their normal text form (no zero padding). This is a
deliberate change from 1.6.2 (D4).

## 10. Packet index (`-I`)

For each flow file `F`, the index file is `F.findx`. It has one line per
stored segment:

```
<offset>|<seconds>.<microseconds, 6 digits>|<length>
```

`length` is the number of bytes written after `-b` truncation. When the
flow is closed, lines are sorted by offset with a stable sort.

## 11. Per-flow pcap (`-K`)

With `-K`, no reassembly is done. Each packet whose TCP ports can be read
(at least 4 bytes of TCP header captured) is appended to the pcap file of
its flow:

- the name is the template expansion with counter 0, plus `.pcap`;
- the pcap header uses the link type of the input and snaplen 65535;
- each record holds the original timestamp, captured length, original
  length and captured bytes.

Files are opened and closed under the limit of section 8 (D3).

## 12. Unprocessed packets (`-w`)

With `-w file`, every IPv4 or IPv6 packet that is not processed as TCP
(section 4) is written to `file` in pcap format. Non-IP frames are not
written. The pcap header (link type, snaplen) is copied from the first
`-r` file. `-w` requires at least one `-r`.

## 13. Post-processing

Post-processors run on each flow file when the flow is closed, if the
file has at least one byte. They require stored output, so `-FX` combined
with any post-processor is a fatal error.

### 13.1 MD5 (`md5`, `-FM`, `-a`)

Adds `<hashdigest type='MD5'>…</hashdigest>` with the lowercase hex MD5 of
the flow file to its `<fileobject>`.

### 13.2 HTTP (`http`, `-a`, `-e http`)

Applies to flow files of at least 80 bytes that start with `HTTP/1.`
(server responses). The file is parsed as a sequence of HTTP/1.x
responses. Parsing stops on a parse error or an `Upgrade` response.

For response number `n` (starting at 1) with a body:

- the body file is `<flow file>-HTTPBODY-<n, 3 digits>`, plus `.<ext>` if
  the `Content-Type` maps to an extension (mime table, identical to
  1.6.2);
- chunked transfer encoding is removed;
- `Content-Encoding: gzip` or `deflate` bodies are decompressed unless
  `-Z`. A decompression error stops writing that body;
- a body file that would be empty is not created.

Each body file adds to the flow's `<fileobject>`:

```xml
<byte_runs>
  <byte_run file_offset='O'><fileobject><filename>BODY</filename>…</fileobject></byte_run>
</byte_runs>
```

`O` is the offset of the body in the flow file.

### 13.3 netviz (`netviz`, `-a`)

Writes a one-page PDF summary `<outdir>/report.pdf`. Phase 3. The content
should match 1.6.2 (time histogram, address and port histograms,
packetfall); the rendering is level C.

### 13.4 Parameters (`-S`)

| Name | Meaning | Phase |
|---|---|---|
| `enable_report=0` | Do not write the DFXML report. | 1 |
| `tdelta=N` | Add `N` seconds to every packet timestamp. | 1 |
| `tcp_timeout=N` | Close flows idle for more than `N` seconds (section 5.4). | 1 |
| `tcp_cmd=CMD` | After a flow is closed, run `CMD` with the flow file path as one extra argument (D7). At most 10 at a time. | 2 |
| `http_cmd=CMD` | The same for each HTTP body file. | 2 |
| `tcp_alert_fd=N`, `http_alert_fd=N` | Write `open\t<path>` and `close\t<path>` lines to descriptor `N`. | 3 |
| `packet-buffer-timeout=N` | libpcap read timeout in milliseconds for live capture. | 2 |

An unknown parameter name is a warning, not an error.

## 14. Report (`report.xml`)

The report is written unless `-c` or `-S enable_report=0`. It is a DFXML
document:

```xml
<?xml version='1.0' encoding='UTF-8'?>
<dfxml xmloutputversion='1.0'>
  <metadata xmlns='http://afflib.org/tcpflow/' …>…</metadata>
  <creator version='1.0'>
    <program>TCPFLOW</program>
    <version>2.0.0</version>
    <execution_environment>
      <command_line>…the actual command line…</command_line>
      <start_time>…</start_time>
      …
    </execution_environment>
  </creator>
  <configuration><tdelta>0</tdelta></configuration>
  <fileobject>…</fileobject>   <!-- one per closed flow, in close order -->
  …
  <summary>
    <total_flows>N</total_flows>
    <total_packets>N</total_packets>
    <max_open_flows>N</max_open_flows>
  </summary>
  <rusage>…</rusage>
</dfxml>
```

Each `<fileobject>` (level B):

```xml
<fileobject>
  <filename>PATH</filename>          <!-- omitted if no file was created -->
  <filesize>N</filesize>             <!-- logical stream size, section 6 -->
  <tcpflow startime='ISO8601' endtime='ISO8601'
           mac_daddr='…' mac_saddr='…'  family='2|10'
           src_ipn='…' dst_ipn='…' srcport='N' dstport='N' packets='N'
           out_of_order_count='N' violations='N' len='N' caplen='N'/>
  <hashdigest type='MD5'>…</hashdigest>   <!-- with md5 -->
  <byte_runs>…</byte_runs>                 <!-- with http -->
</fileobject>
```

- Timestamps are ISO 8601 UTC with microseconds.
- `mac_*` is present only for Ethernet.
- `out_of_order_count` and `violations` are present only if non-zero.
- `caplen` is present only if it differs from `len`.
- `family` is the platform's `AF_INET` / `AF_INET6` value, as in 1.6.2.

## 15. Conformance tests

`tests/golden/` holds the output of the reference binary for every pcap in
`tests/` and `samplePcaps/`, for these runs:

| Name | Options |
|---|---|
| `default` | (none) |
| `all` | `-a` |
| `index` | `-I -Ft` |
| `bins` | `-Fk -Fc` |
| `template` | `-T %T-%A.%a-%B.%b-%#` |
| `limit` | `-b 100` |
| `pcap` | `-K` |
| `console` | `-c` |
| `console-hdr` | `-C -s` |
| `hex` | `-c -D` |

For each run the golden data contains:

- every created file (level A), except `report.xml` and `report.pdf`;
- the `<fileobject>` elements of `report.xml`, normalised: one element
  per line, attributes sorted (level B);
- stdout for the console runs (level A);
- file modification times.

`tests/conformance.py check <tcpflow>` runs every case, compares the
results and prints `N of M cases match`. A case that differs only
because of an intentional difference is recorded in
`tests/golden/EXPECTED_DIFFERENCES` with the reason.

The golden data is not taken on trust:

- `tests/conformance.py generate <reference>` refuses to write golden data
  if any case hangs (30 seconds) or crashes. A hang or a crash is always a
  bug, in the reference or in 2.0, never expected behaviour;
- when 2.0 differs from the golden data, the difference is investigated
  first. If 1.6.2 is wrong, the fix goes into section 17 and, where it
  is cheap, into 1.x as well, and the golden data is regenerated.

## 16. Privilege dropping (`-U`, `-z`)

As specified for 1.6.2 by #281:

- `spec` is `user`, `uid`, `user:group`, `uid:gid` or `:group`. Each part
  is looked up as a name first, then parsed as a number;
- privileges are dropped once, right after the first input or the
  capture device is opened. Inputs opened later must be readable by the
  new user;
- before dropping, the output directory (if tcpflow created it), the
  `-w` file and the report are handed to the new ids with `lchown`;
- supplementary groups are set with `initgroups` for a named user, and
  cleared otherwise;
- `-z` requires the target uid to be non-zero;
- any failure is fatal. tcpflow never continues with privileges it was
  asked to drop.

## 17. Intentional differences from 1.6.2

| ID | 1.6.2 behaviour | 2.0 behaviour |
|---|---|---|
| D1 | The VLAN ID in file names is the whole 16-bit TCI, priority bits included (VLAN 42 with priority 5 becomes `41002`). | The VLAN ID is `TCI & 0x0fff`. |
| D2 | `report.xml` opens `<configuration>` twice, nests all `<fileobject>` elements in the second one, puts wifi `<ssids>` in `<summary>`, and writes `command line to be provided` instead of the command line. | The structure of section 14. |
| D3 | `-K` keeps every per-flow pcap file open until exit and fails with EMFILE on large captures. | The open file limit of section 8 applies. |
| D4 | `-J` derives addresses and ports by splitting the file name at `.` and `-`; the result is wrong for IPv6 and for custom templates. | Addresses and ports come from the flow key. |
| D5 | `-V` exits with status 1. | `-V` exits with status 0. |
| D6 | Compressed inputs are decompressed by a shell command with the file name in single quotes; a name containing `'` runs arbitrary commands. | In-process decompression, no shell. |
| D7 | `tcp_cmd` and `http_cmd` run `system(CMD + " " + path)`. | `sh -c 'CMD "$1"' tcpflow PATH`: the path is never parsed by the shell. |
| D8 | `SYN TO IGNORE!` is printed to stderr for every ignored SYN. | Printed only at debug level ≥ 2. |
| D9 | Flow file times use `futimes` with the flow start time; on failure a message is printed and processing continues. | Same, without the message unless debug level ≥ 1. |
| D10 | `DLT_NULL` compares the family with the reading host's `AF_INET`/`AF_INET6` constants, so a macOS or BSD IPv6 capture is not decoded on Linux and vice versa. | The family values of all common platforms are accepted, in either byte order. |
| D11 | `-Fc` replaces `%c` with `%C`, so the name loses the counter. A second flow with the same name makes the search for a free name loop forever. | Fixed in 1.x as well (`fix/fc-counter`); see section 7.2. |
| D12 | `SIGTERM` and `SIGINT` only stop the packet loop; a process stuck elsewhere ignores them. | `SIGTERM` and `SIGINT` stop processing promptly; open flows are closed and the report is written. |

Differences that only affect level C outputs are not listed.

## 18. Out of scope

- IP fragment reassembly.
- IPv6 extension headers (phase 3).
- The SQLite flow database and `-S` options of unused 1.6.2 code paths.
- Windows (1.6.2 supported mingw builds; 2.0 targets Linux, macOS and the
  BSDs first).
