# Captures

Every `.pcap` and `.pcapng` file here is run by `tests/scripts/conformance.py`.
The 1.x name is the file's name on the `main` branch and in the `fix/*` branches.

## http/

| File | Contents | 1.x name |
|---|---|---|
| `two-connections.pcap` | Two HTTP connections to a web server, both directions. The basic case. | `tests/test1.pcap` |
| `two-connections-part1.pcap`, `-part2.pcap` | `two-connections` cut in two, for `-r` then `-R`. | `tests/test1-part1.pcap`, `-part2.pcap` |
| `one-direction.pcap` | One direction of the first connection. | `tests/test1-80-50955.pcap` |
| `one-packet.pcap` | A single packet of it. | `tests/test1-one-packet.pcap` |
| `out-of-order.pcapng` | Two packets of the first response, as pcapng (also the `-w` pcapng test of 1.x). | `tests/test1-out-of-order.pcap` |
| `text-lines.pcap` | An HTTP exchange of numbered text lines, in order. | `tests/test5-lines.pcap` |
| `text-lines-shuffled.pcapng` | The same, shuffled. | `tests/test5-lines-randomized.pcap` |
| `text-lines-before-start.pcapng` | The same, without the SYN and with data before the first packet (SPEC.md 6.2, D37). | `tests/test5-lines-randomized2.pcap` |
| `gzip-body.pcap` | A gzip-encoded HTTP body. | `tests/test-gzip.pcap` |
| `large-body.pcap` | A 62 KB HTTP body. | `tests/bug2.pcap` |
| `byte-runs.pcap` | An HTTP response; added in 1.x with the recording of byte extents. | `tests/bug3.pcap` |
| `curl-two-requests.pcap` | Two curl requests over two connections. | `tests/bug6.pcap` |
| `browser-page-load.pcap` | A browser loading a page over several connections. | `tests/airsnort-linux-browser_page_load.pcap` |
| `jpegs.pcap` | 38 flows of web traffic with images; many HTTP bodies. | `samplePcaps/jpegs.cap` |
| `image/image.pcapng` | An HTML page and an image over one connection, on loopback. `body-001.html` and `body-002.jpg` are the bodies `-a` must extract. | `tests/test8/` |

## ipv6/

| File | Contents | 1.x name |
|---|---|---|
| `http.pcap` | HTTP over IPv6, Ethernet. | `tests/test3.pcap` |
| `raw-ip-http.pcap` | HTTP over IPv6, raw IP (LINKTYPE 101), 12 flows. | `tests/test4.pcap` |
| `raw-ip-bad-timestamps.pcap` | Raw IP (link type 12) with out-of-range microseconds. | `tests/bug8.pcap` |

## link/

| File | Contents | 1.x name |
|---|---|---|
| `vlan.pcap` | TCP inside 802.1Q tags (VLAN 42). | `tests/test2.pcap` |
| `null-loopback.pcap`, `null-loopback-2.pcap` | BSD loopback (`DLT_NULL`) with IPv4 and IPv6, ssh and more. | `tests/local.pcap`, `tests/local2.pcap` |
| `wifi-80211.pcap`, `wifi-prism.pcap`, `wifi-radiotap.pcap` | `two-connections` as 802.11 data frames, bare, behind Prism and behind radiotap; made by `tests/scripts/make-wifi.py`. | `tests/wifi-80211.pcap` (`fix/ieee80211-dlt`) |

## edge/

| File | Contents | 1.x name |
|---|---|---|
| `snaplen-40.pcap` | Captured with snaplen 40: TCP headers are cut, nothing is processed. | `tests/simson.pcap` |
| `truncated-tcp.pcap` | One packet with a short TCP header. | `tests/truncated-tcp.pcap` (`fix/dissect-tcp-bounds`) |
| `udp-only.pcap` | UDP and IPv6 without TCP: everything goes to `-w`. | `tests/udp.pcap` |
| `handshake-only.pcap` | A connection without data. | `tests/bug4.pcap` |
| `rst.pcap` | Segments with RST; added in 1.x for the inspection of RST packets. | `tests/bug5.pcap` |
| `retransmissions.pcap` | A binary protocol with repeated segments. | `tests/bug7.pcap` |
| `three-sessions.pcap` | Three sessions between the same two ports. | `tests/test7-three-flows.pcap` (and the identical `tests/flow_test.pcap`) |
