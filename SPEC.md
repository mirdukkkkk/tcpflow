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
| `-i iface` | Live capture on `iface` (section 3.1). Without `-r` or `-R` (or `-l` files), capture on the first device libpcap reports. `-i` with `-r` or `-R` is an error (D27). | 2 |
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
| `-s` | Replace non-printable bytes with `.` in console output. This is the default. | 1 |
| `-B` | Raw bytes in console output instead of replacing non-printable ones. | 1 |
| `-0` | No newline after each console packet. | 1 |
| `-g` | Color console output by direction. | 1 |
| `-J` | Console output as JSON lines (section 9.3). Without `-C`, implies `-c` (D21). | 2 |
| `-I` | Write a `.findx` packet index next to each flow file (section 10). | 1 |
| `-K` | Write one pcap file per flow instead of reassembled data (section 11). | 2 |
| `-w file` | Write IP packets that were not processed as TCP to a pcap file (section 12). Needs `-r` or live capture. | 2 |
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
| `-L name` | Serialise console output across processes with a named semaphore (section 9.4). | 3 |
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

### 3.1 Live capture

Without input files, tcpflow captures on a device: the `-i` device, or
the first one `pcap_findalldevs` reports. A device that cannot be opened
is a fatal error (exit status 1) with the libpcap message. The capture
uses snaplen 65536, promiscuous mode unless `-p`, and the read timeout
`packet-buffer-timeout` (default 10 ms). `listening on <device>` is
printed at debug level 1. Capture runs until SIGINT, SIGTERM or SIGHUP
(D12); then flows are closed and the report is written as for a file.

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
| `IEEE802_11` (105), `IEEE802_11_RADIO` (127), `PRISM_HEADER` (119) | 802.11 data frames with LLC/SNAP (section 4.1.1). |

An unsupported link type is a fatal error: `unknown datalink type N`.

#### 4.1.1 802.11

- Radiotap (127): the header is `it_len` bytes. If the flags field is
  present, its FCS bit says whether the frame ends in an FCS, and its
  DATAPAD bit pads the 802.11 header to a multiple of 4 bytes (D30). A
  frame with the bad-FCS flag is ignored.
- Prism (119): a 144-byte header.
- Without radiotap flags (105, 119, or radiotap without the field), the
  last 4 bytes are an FCS if they are the CRC-32 of the rest of the
  frame. An FCS is removed; a frame whose FCS is wrong is ignored (D29).
- Only data frames are decoded. Subtypes without data (Null, QoS Null,
  CF-only), protected (encrypted) frames and A-MSDUs are ignored.
- The header is 24 bytes, plus 6 with both to-DS and from-DS (a fourth
  address), plus 2 for QoS subtypes, plus 4 for HT control in a QoS frame
  with the order bit (D30).
- The header is followed by LLC/SNAP `AA AA 03`, OUI `00 00 00` or
  `00 00 F8`, and EtherType 0x0800 or 0x86dd. Anything else is ignored.
- MAC addresses are not reported for 802.11 (section 14).

`tests/make-wifi.py` turns an Ethernet capture into the three 802.11
test captures.

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

The payload length is clamped to the captured bytes. A payload length
of 0 (TCP segmentation offload, or a jumbogram) uses the captured
length, as for IPv4.

Extension headers are followed to TCP (D28): Hop-by-Hop Options (0),
Routing (43), Destination Options (60), each `(len + 1) × 8` bytes,
Authentication (51), `(len + 2) × 4` bytes, and Fragment (44), 8 bytes.
The TCP length is the payload length minus the extension headers.

The packet is ignored when:

- fewer than 40 bytes are captured;
- a header other than these is reached before TCP, for example ESP (50),
  No Next Header (59) or UDP;
- an extension header does not fit in the payload (or the captured
  bytes);
- it is a fragment with a non-zero offset. The first fragment is
  processed, as for IPv4.

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

With `-c`, `-C` or `-J`, segments are printed in arrival order. No
reassembly is done.

### 9.1 Text

For each segment with data:

1. if `-g`, the color: `ESC[0;34m` for a flow whose first SYN had no ACK
   (client to server), else `ESC[0;31m`;
2. unless `-C` or `-J`: the flow name (section 7, counter 0, with the
   `<outdir>/` prefix as for files), then `: `, then a newline if `-D`;
3. the data:
   - by default, each byte that is not printable ASCII (0x20–0x7e), `\n` or
     `\r` is replaced by `.` (`-s` asks for this explicitly);
   - with `-B`, the raw bytes;
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

Step 3 of 9.1 prints one JSON object per segment (exactly this spacing,
including the space after `"payload":`):

```json
{"src_host":"192.168.1.102","src_port":50955,"dst_host":"74.125.19.104","dst_port":80,"payload": [71,69,84]}
```

`payload` holds the bytes as decimal numbers, after `-b` truncation.
Addresses and ports come from the flow key, addresses in their normal
text form (D4). `-D` takes precedence over `-J`; `-B` and `-s` have no
effect. `-g` and `-0` work as in 9.1.

### 9.4 Semaphore (`-L`)

With `-L name`, the POSIX named semaphore `name` is opened at start,
created with the value 1 (mode 0666 minus the umask) if it does not
exist. It is taken before each segment is printed and released after the
segment is written to stdout, so several tcpflow processes that share a
terminal or pipe never mix their segments. A semaphore that cannot be
opened is a fatal error (D34). Without console output, `-L` has no
effect. A process killed while it holds the semaphore leaves it taken;
remove it with `sem_unlink`, or on Linux `/dev/shm/sem.<name>`.

## 10. Packet index (`-I`)

For each flow file `F`, the index file is `F.findx`. It has one line per
stored segment:

```
<offset>|<seconds>.<microseconds, 6 digits>|<length>
```

`length` is the number of bytes written after `-b` truncation. When data
is shifted because it arrived before the guessed ISN (section 6.2), every
existing offset grows by the same amount, so offsets always point at the
data. When the flow is closed, lines are sorted by offset with a stable
sort (D16).

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

With `-w file`, every frame that the link layer hands on as IP
(section 4.1) but that is not processed is appended to `file` in pcap
format. Not processed means:

- it is not IPv4 or IPv6 after all: fewer than 20 bytes, or a version
  nibble other than 4 or 6;
- it is ignored by the rules of sections 4.2 to 4.4 (not TCP, a
  fragment, a bad header length, fewer than 20 bytes of TCP header, or
  fewer than 4 with `-K`);
- it is a SYN that is ignored on an open flow (section 5.2).

Frames the link layer drops (for example ARP on Ethernet, or an unknown
`DLT_NULL` family) are not written. Packets of `-R` files that belong to
no open flow are processed (and dropped) and are not written either.

The file is created when the first `-r` file or the capture device is
opened. libpcap writes its header, with the link type and snaplen of
that input, so pcapng, big-endian and compressed inputs work (D20). Each
record holds the original timestamp, the captured length, the original
length and the captured bytes. `-w` requires at least one `-r` or live
capture (D26).

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
| `tcp_cmd=CMD` | After a flow is closed, run `CMD` with the flow file path as one extra argument (section 13.5, D7). | 2 |
| `http_cmd=CMD` | The same for each HTTP body file. | 2 |
| `tcp_alert_fd=N`, `http_alert_fd=N` | Write `open\t<path>` and `close\t<path>` lines to descriptor `N` (section 13.5). | 3 |
| `packet-buffer-timeout=N` | libpcap read timeout in milliseconds for live capture. | 2 |

An unknown parameter name is a warning, not an error.

### 13.5 Commands and alerts

- `tcp_alert_fd=N`: `open\t<path>\n` when a flow file is created, and
  `close\t<path>\n` when the flow is closed. Reopening a file after the
  open file limit (section 8) writes nothing (D32). Flows without a file
  write nothing.
- `http_alert_fd=N`: `open` and `close` lines for each HTTP body file
  that is kept (section 13.2). Bodies are extracted when their flow is
  closed, so the lines of a body come together, before the `close` of
  its flow.
- `N` must be an open descriptor when tcpflow starts, otherwise it is a
  fatal error. tcpflow never closes it, and `tcp_alert_fd` and
  `http_alert_fd` may be the same. After a failed write, an error is
  printed and nothing more is written to it.
- `tcp_cmd=CMD` and `http_cmd=CMD` run `sh -c 'CMD "$1"' tcpflow PATH`
  for each closed flow file and each kept body file, after its alert
  lines (D7). At most 10 commands of each kind run at a time; tcpflow
  waits for the oldest one before starting another. Before exiting,
  tcpflow waits for all of them (D33). A command that cannot be started
  is reported; processing continues.
- With `-K`, no commands are run and no alerts are written, as in 1.6.2.

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
- `mac_*` is present only for Ethernet, and only if the address is not all zeros.
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
| `unprocessed` | `-w out/unprocessed.pcap` |
| `console` | `-c` |
| `console-hdr` | `-C -s` |
| `hex` | `-c -D` |
| `json` | `-c -J` |

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

Based on #281, with the problems found in its review fixed (D22–D24):

- `spec` is `user`, `uid`, `user:group`, `uid:gid` or `:group`. Each part
  is looked up as a name first, then parsed as a decimal number
  (`4294967295`, which is `(uid_t)-1`, is rejected). A user gives its
  primary group unless a group is named. A numeric uid without a passwd
  entry needs an explicit group (D24). `:group` keeps the current uid.
  An invalid spec is reported as `-U <spec>: ...` before anything is
  created, with exit status 1;
- privileges are dropped once, right after the first input or the
  capture device is opened and the `-w` file is created. Inputs opened
  later must be readable by the new user;
- before dropping, the output directory, the report and the `-w` file
  are handed to the new ids with `fchown` on the descriptors tcpflow
  holds, never by path (D22), and only if tcpflow created them: an
  existing file, a device such as `/dev/null` or the target of a symlink
  is never given away (D23). It is still written through the descriptor
  opened before the drop;
- the order is `fchown`, `chroot` and `chdir("/")`, supplementary
  groups (`initgroups` for a user with a passwd entry, otherwise only
  the target group), `setgid`, `setuid`. After a drop to a non-root uid,
  `setuid(0)` and `seteuid(0)` must fail;
- `-z dir` requires `-U` with a non-root uid. The output directory
  `-o O` is `dir/O` before and after the chroot, and the default report
  is created there too. `-X`, `-w` and the first input are opened before
  the chroot with ordinary paths; later inputs are opened inside it;
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
| D10 | `DLT_NULL` reads only the first byte of the family and compares it with the reading host's `AF_INET`/`AF_INET6`, so a macOS or BSD IPv6 capture, or any big-endian capture, is not decoded. | The family values of all common platforms are accepted, in either byte order. Fixed in 1.x as well (`fix/null-family`). |
| D11 | `-Fc` replaces `%c` with `%C`, so the name loses the counter. A second flow with the same name makes the search for a free name loop forever. | Fixed in 1.x as well (`fix/fc-counter`); see section 7.2. |
| D12 | `SIGTERM`, `SIGINT` and `SIGHUP` only stop the packet loop; a process stuck elsewhere ignores them. | They stop processing promptly; open flows are closed and the report is written. |
| D13 | The MAC addresses in `report.xml` are copied from the first 12 bytes of every frame, so loopback and raw IP captures get garbage `mac_daddr`/`mac_saddr` values. | MAC addresses only for Ethernet. Fixed in 1.x as well (`fix/report-mac`). |
| D14 | An IPv6 packet with payload length 0 has no TCP data. | The captured length is used, as for IPv4 (section 4.3). |
| D15 | Report timestamps drop the fraction when the microseconds are 0 (`…:41Z` instead of `…:41.000000Z`, #206). | Always 6 digits of microseconds. |
| D16 | `.findx` offsets are not adjusted when data is shifted (6.2), so they point at the wrong bytes; the index is never sorted although the documentation says so. | Offsets follow the data and the index is sorted. Fixed in 1.x as well (`fix/findx-offsets`). |
| D17 | `-FM` enables the MD5 post-processor but not post-processing itself, so no digest is ever written. | `-FM` adds MD5 digests (13.1). |
| D18 | Post-processing is skipped for a flow whose content is identical to an earlier flow (bulk_extractor's duplicate detection), so it gets no MD5 and its HTTP bodies are not extracted. | Every flow is post-processed. |
| D19 | `-K` files of Ethernet captures have link type 6 (Token Ring), so tcpdump and Wireshark decode every packet wrongly. | The link type of the input. Fixed in 1.x as well (`fix/k-linktype`). |
| D20 | `-w` copies the first 24 bytes of the first `-r` file as the pcap header and aborts if they are not a little-endian pcap header, so a pcapng, big-endian or compressed input makes tcpflow crash. | libpcap writes the header (section 12). Fixed in 1.x as well (`fix/w-pcapng`). |
| D21 | `-J` only changes the output of `-c` and `-C`; on its own it is silently ignored and flow files are written. | `-J` without `-C` implies `-c`. |
| D22 | (#281) Ownership is handed over with `lchown` by path, after the output directory already belongs to the new user, so a process of that user can swap the directory for a symlink and make root change the owner of other files. | `fchown` on descriptors (section 16). |
| D23 | (#281) The report and the `-w` file are handed over even if they existed or are devices: `-U nobody -w /dev/null` gives `/dev/null` to `nobody`. | Only outputs tcpflow created are handed over. |
| D24 | (#281) A numeric uid without a passwd entry keeps gid 0. | An explicit group is required. |
| D25 | (#281) With `-z`, the output directory and the report are created relative to the working directory before the chroot, but flow files relative to the chroot. | `-o` is inside the chroot for both (section 16). |
| D26 | `-w` with live capture fails: "currently the -w option requires the -r option". | Allowed; the header has the device's link type (section 12). |
| D27 | `-i` with `-r` or `-R` is silently ignored and the files are read. | An error. |
| D28 | An IPv6 packet whose next header is not TCP is not processed, so TCP after an extension header is lost (it goes to `-w`). | Extension headers are followed (section 4.3). |
| D29 | The last 4 bytes of every 802.11 frame are taken as the FCS. With the default `check_fcs=1`, a frame without a valid FCS is dropped, so a capture without FCS (as many drivers deliver it) yields nothing; with `check_fcs=0` every packet loses 4 bytes. `DLT_IEEE802_11` (105) is parsed as radiotap and yields nothing. | The FCS is detected (section 4.1.1). 105 fixed in 1.x as well (`fix/ieee80211-dlt`). |
| D30 | QoS is recognised only for subtype 8; HT control and the radiotap DATAPAD flag are not handled, so the LLC header is looked for at the wrong place. | Section 4.1.1. |
| D31 | The child that runs `tcp_cmd` or `http_cmd` ends with `exit()`, which moves the read position of the input file it shares with tcpflow, so tcpflow reads garbage (`invalid packet capture length`) and stops early. | Commands do not touch tcpflow's files. Fixed in 1.x as well (`fix/cmd-exit`). |
| D32 | `open` is written again each time a flow file is reopened after the open file limit; a flow without a file writes `close` with an empty path. | `open` once, when the file is created; nothing for flows without a file. |
| D33 | tcpflow exits without waiting for running commands. The limit of 10 counts any finished child, of either kind. | tcpflow waits for its commands; each kind has its own limit. |
| D34 | `-L` always fails with `(null): attempt to create lock pthreads not present`, because `configure` never defines `HAVE_PTHREAD_H`; the semaphore calls themselves are behind `HAVE_PTHREAD`, which is never defined either. A failing `sem_open` is not checked. | Section 9.4. Fixed in 1.x as well (`fix/semlock`). |

Differences that only affect level C outputs are not listed.

## 18. Out of scope

- IP fragment reassembly.
- The SQLite flow database and `-S` options of unused 1.6.2 code paths.
- Windows (1.6.2 supported mingw builds; 2.0 targets Linux, macOS and the
  BSDs first).
