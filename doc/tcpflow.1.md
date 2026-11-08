---
title: TCPFLOW
section: 1
header: User Commands
footer: tcpflow 2.0.0-dev
date: November 8, 2026
---

<!--
The source of the man page. After editing, regenerate doc/tcpflow.1 with
doc/manpage.sh (needs pandoc). Every option of src/cli.rs must be described
here (tests/manpage.rs checks it); CI checks that doc/tcpflow.1 is up to
date (doc/manpage.sh --check).
-->

# NAME

tcpflow - TCP flow recorder

# SYNOPSIS

**tcpflow** [**-aBcCDgIJKlpqsvVZ0**] [**-b** *max_bytes*] [**-d** *level*]
[**-e**|**-x**|**-E** *name*] [**-f** *max_fds*] [**-F** *flags*]
[**-i** *iface*] [**-L** *name*] [**-m** *bytes*] [**-o** *outdir*]
[**-r** *file*]... [**-R** *file*]... [**-S** *name*=*value*]...
[**-T** *template*] [**-U** *user*[:*group*]] [**-w** *file*] [**-X** *file*]
[**-z** *dir*] [*expression*]

# DESCRIPTION

**tcpflow** captures data transmitted as part of TCP connections (flows)
and stores it in a way that is convenient for protocol analysis and
debugging. Rather than showing packet by packet information, **tcpflow**
reconstructs the actual data streams and stores each flow in its own file.
It understands TCP sequence numbers and reconstructs the streams correctly
regardless of retransmissions or out-of-order delivery. A typical
connection gives two files, one for each direction.

**tcpflow** reads packets from capture files (**-r**, **-R**, **-l**) or,
without them, captures live from a network interface (**-i**). Capture
files may be pcap or pcapng, and may be compressed with gzip (*.gz*), bzip2
(*.bz2*), xz or lzma (*.xz*, *.lzma*) or zip (*.zip*, the first entry);
**tcpflow** decompresses them itself.

The optional *expression* is a libpcap filter (see **pcap-filter**(7)), such
as **'tcp port 80'**. All remaining arguments are joined with spaces, so the
expression may be given as one quoted argument or as several. Only packets
that match it are processed.

Supported link layers are Ethernet (with VLAN tags), Linux cooked capture,
raw IP, BSD loopback (NULL and LOOP), PPP, Token Ring and 802.11 (plain,
radiotap and Prism). IPv4 and IPv6 are supported; IP fragments are not
reassembled.

When a flow is closed (FIN, RST, **tcp_timeout** or the end of input),
**tcpflow** runs the post-processors (**-a**, **-e**) on its file and adds
the flow to the DFXML report.

# OPTIONS

## Input

**-r** *file*
:   Read packets from a capture file. May be repeated; the files are read
    in order. **-** is standard input.

**-R** *file*
:   Read a capture file only to finish flows that are already open: no new
    flows are created. The **-R** files are read after all **-r** files.
    This is meant for a series of files captured over time: process file
    *n* with **-r** *file(n)* and file *n+1* with **-R** *file(n+1)*. May be
    repeated.

**-l**
:   Treat the remaining arguments as capture files, as if each had a **-r**
    in front, instead of a filter expression. For example
    **tcpflow -o out -l \*.pcap** reads all pcap files in the current
    directory.

**-i** *iface*
:   Capture live on the network interface *iface*. Without **-i**, **-r**,
    **-R** or **-l**, **tcpflow** captures on the first interface libpcap
    reports. **-i** together with input files is an error. Live capture
    runs until SIGINT, SIGTERM or SIGHUP; then the open flows are closed
    and the report is written.

**-p**
:   Do not put the interface into promiscuous mode. It may already be in
    promiscuous mode for another reason.

## Output files

**-o** *outdir*
:   Write flow files and the report into *outdir*, default the current
    directory. The directory is created (one level) if it does not exist.

**-T** *template*
:   Name flow files with *template* (see **FILE NAMES**). If the template
    has no **%c**, **%C%c** is appended.

**-F** *flags*
:   File name and output flags, applied in the order given; several may be
    combined, as in **-Fct**. Because **-T** replaces the whole template,
    flags given before it are lost.

    **c**
    :   Always append the connection counter: the first file gets **c0**.

    **t**
    :   Prepend the flow start time in Unix seconds and **T**.

    **T**
    :   Prepend the flow start time in ISO 8601.

    **k**
    :   Put flow files into directories of 1000 flows (**%K/**).

    **m**
    :   Two directory levels, for up to a million flows.

    **g**
    :   Three directory levels, for up to a billion flows.

    **X**
    :   Store no flow files; the report is still written. Cannot be
        combined with post-processors.

    **M**
    :   Add the MD5 of every flow to the report (the **md5**
        post-processor).

**-b** *max_bytes*
:   Store at most *max_bytes* bytes of each flow; the rest is discarded.
    The default is no limit.

**-m** *bytes*
:   A sequence number gap of more than *bytes* starts a new flow file (with
    the next connection counter). The default is 16777216 (16 MiB).

**-f** *max_fds*
:   Keep at most *max_fds* flow files open at once. When the limit is
    reached, the least recently written file is closed and reopened later.
    The default is the process file limit minus 6; with **-I** it is
    halved.

**-X** *file*
:   Write the DFXML report to *file* instead of *outdir*/report.xml.

**-I**
:   Write a packet index *F*.findx next to each flow file *F*. It has one
    line per stored segment:

        offset|seconds.microseconds|length

    where *offset* is the position in the flow file and *length* the number
    of bytes stored. The lines are sorted by offset when the flow is
    closed.

**-K**
:   Write one pcap file per flow instead of the reassembled data. The name
    is the flow file name plus **.pcap**; flows whose names are the same
    share a file. No post-processors, commands or alerts run with **-K**.

**-w** *file*
:   Write the IP packets that were not processed as TCP (UDP, ICMP,
    fragments, malformed packets, ignored SYNs) to *file* in pcap format.

**-q**
:   Do not warn when the output directory ends up with 10000 files or more
    (see **-Fk**).

## Console output

**-c**
:   Print the data of each segment to standard output, in arrival order,
    instead of writing files. Each segment is preceded by the flow name and
    **": "**. No report is written.

**-C**
:   Like **-c**, without the flow name. Unlike **-c**, the report is still
    written.

**-s**
:   Replace bytes that are not printable ASCII, newline or carriage return
    with **.** when printing. This is the default.

**-B**
:   Print the bytes as they are.

**-D**
:   Print a hex dump, 32 bytes per line. Implies **-B**.

**-0**
:   Do not print a newline after each segment.

**-g**
:   Colour each segment by direction: blue for client to server, red for
    server to client.

**-J**
:   Print each segment as a JSON line with **src_host**, **src_port**,
    **dst_host**, **dst_port** and **payload** (the bytes as numbers).
    Implies **-c** unless **-C** is given.

**-L** *name*
:   Take the POSIX named semaphore *name* around each printed segment, so
    that several **tcpflow** processes printing to the same terminal or
    pipe do not mix their output. The semaphore is created with value 1 if
    it does not exist.

## Post-processing

**-a**
:   Run all post-processors: the same as **-e all**.

**-e** *name*
:   Enable a post-processor:

    **http**
    :   Extract the body of each HTTP response in a server-to-client flow
        into *flowfile*-HTTPBODY-*nnn*.*ext*, where *nnn* is the response
        number from 001 and *ext* comes from the **Content-Type**. Chunked
        encoding is removed, and gzip and deflate bodies are decompressed
        unless **-Z**. A body is written up to **http_max_body** bytes.

    **md5**
    :   Add the MD5 of every flow file to the report.

    **all**
    :   Both.

    **netviz**, **tcpdemux** and **wifiviz** are accepted for old command
    lines and do nothing.

**-x** *name*
:   Disable a post-processor.

**-E** *name*
:   Disable all post-processors, then enable *name*.

**-Z**
:   Do not decompress gzip or deflate HTTP bodies.

**-S** *name*=*value*
:   Set a parameter (see **PARAMETERS**). May be repeated.

## Privileges

**-U** *spec*, **\--relinquish-privileges**=*spec*
:   Drop root privileges once the first input or the capture device is
    open. *spec* is *user*, *uid*, *user*:*group*, *uid*:*gid* or
    :*group*. A user gives its primary group unless a group is named; a
    numeric uid without a passwd entry needs a group. Before dropping, the
    output directory, the report and the **-w** file are handed to the new
    user if **tcpflow** created them. Inputs opened later must be readable
    by the new user. Any failure is fatal.

**-z** *dir*, **\--chroot**=*dir*
:   Change the root directory to *dir* when dropping privileges. Needs
    **-U** with a user other than root. The output directory **-o** *O* is
    *dir*/*O*.

## Other

**-d** *level*
:   Debug level for messages on standard error: 0 is silent, 1 (the
    default) prints minimal status, 10 is verbose, higher levels are for
    developers.

**-v**, **\--verbose**
:   The same as **-d 10**.

**-V**, **\--version**
:   Print the version and exit.

**-h**, **\--help**
:   Print the options and exit; **-hh** also prints the parameters and file
    name codes.

# PARAMETERS

Set with **-S** *name*=*value*. An unknown name is a warning.

**enable_report=**0
:   Do not write the report.

**tdelta=***N*
:   Add *N* seconds to every packet timestamp.

**tcp_timeout=***N*
:   Close flows that have been idle for more than *N* seconds of capture
    time.

**tcp_cmd=***CMD*
:   After a flow is closed, run *CMD* with the flow file as its last
    argument. The command runs as **sh -c 'CMD "\$1"' tcpflow** *PATH*, so
    the file name is never parsed by the shell. At most 10 commands run at
    a time, and **tcpflow** waits for all of them before it exits.

**http_cmd=***CMD*
:   The same for each HTTP body file.

**tcp_alert_fd=***N*
:   Write a line **open**\\t*path* when a flow file is created and
    **close**\\t*path* when its flow is closed to the open file descriptor
    *N*.

**http_alert_fd=***N*
:   The same for HTTP body files.

**http_max_body=***N*
:   The largest HTTP body file in bytes; 0 means no limit. The default is
    1073741824 (1 GiB).

**packet-buffer-timeout=***N*
:   The libpcap read timeout for live capture in milliseconds, default 10.

# FILE NAMES

The default template is **%A.%a-%B.%b%V%v%C%c**, for example

    192.168.001.103.36322-171.025.221.158.00080

for data sent from 192.168.1.103 port 36322 to 171.25.221.158 port 80. A
new file is never overwritten: while the name exists, the connection
counter is increased, so a second run into the same directory gives
**...c1** files. The codes are:

**%A**, **%B**
:   Source, destination address: four zero-padded octets for IPv4
    (**010.000.000.001**), the usual text form for IPv6.

**%a**, **%b**
:   Source, destination port, 5 digits.

**%E**, **%e**
:   Source, destination MAC address; zeros if not Ethernet.

**%V**, **%v**
:   **\--** and the VLAN ID, if the flow has one.

**%T**, **%t**
:   Flow start time: ISO 8601 UTC (**2017-11-17T22:57:10Z**), Unix
    seconds.

**%c**, **%C**, **%#**
:   The connection counter if it is above 0; **c** if it is above 0; the
    counter always.

**%N**, **%K**, **%M**, **%G**
:   The flow number in groups of 3 digits: units, thousands, millions,
    billions.

**%S**
:   The session ID, 20 digits; both directions of a connection share it.

**%%**
:   A literal **%**.

A **/** in the expanded name creates directories, for example

    tcpflow -r packets.pcap -o out -T %A/%a/%B/%b/%c%N.flow

# REPORT

Unless **-c** or **-S enable_report=0** is given, **tcpflow** writes a DFXML
report, *outdir*/report.xml by default (**-X**). It records the command
line, the system, a summary and one **\<fileobject\>** per closed flow, with
its file name, size and a **\<tcpflow\>** element with the attributes
**startime**, **endtime**, **family**, **src_ipn**, **dst_ipn**,
**srcport**, **dstport**, **packets**, **len**, **caplen** and, if present,
**mac_saddr**, **mac_daddr**, **out_of_order_count** and **violations**.
With **md5** it adds a **\<hashdigest\>**, with **http** a
**\<byte_runs\>** entry for each body file.

# EXIT STATUS

0 on success. 1 for invalid options, an input or device that cannot be
opened, an invalid filter, a failure to drop privileges, or a read error in
an input file (the other files are still processed).

# SECURITY

Files in the output directory are never opened through symbolic links, and
new flow files are created exclusively. Commands from **tcp_cmd** and
**http_cmd** get the file name as an argument, never as shell text. When
capturing as root, use **-U** to drop privileges after the device is open.

# EXAMPLES

Store the flows of a capture file in *out*, with HTTP bodies and MD5
digests:

    tcpflow -a -o out -r capture.pcap

Only port 80, from a compressed file:

    tcpflow -o out -r capture.pcap.gz 'port 80'

Print live traffic to the terminal:

    tcpflow -i eth0 -c

Capture live as root, then run as nobody, with flows binned 1000 to a
directory:

    tcpflow -i eth0 -U nobody -o out -Fk

Traffic between helios and hot or ace, with a report in *flows.xml*:

    tcpflow -X flows.xml -o out host helios and \( hot or ace \)

One pcap file per flow:

    tcpflow -K -o out -r capture.pcap

# BUGS

IP fragments are not reassembled: flows with fragmented packets are not
stored correctly.

Report bugs at
[github.com/simsong/tcpflow/issues](https://github.com/simsong/tcpflow/issues).

# AUTHORS

Originally written by Jeremy Elson; maintained by Simson L. Garfinkel.
tcpflow 2.0 is a rewrite in Rust by mirdukkkkk.

# SEE ALSO

**tcpdump**(1), **pcap**(3PCAP), **pcap-filter**(7), **pcap-savefile**(5)
