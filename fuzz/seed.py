"""Make the starting corpus of the fuzz targets from the test captures.

    python3 -I fuzz/seed.py TCPFLOW

decode: every frame of every classic pcap in tests/captures, prefixed by the
        index of its link type in fuzz_targets/decode.rs.
http:   every server-to-client flow that tcpflow writes for the HTTP
        captures, prefixed by 0 (decompress, large body limit).
"""

import glob
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINKTYPES = [0, 1, 6, 9, 12, 14, 51, 101, 108, 105, 113, 119, 127]


def frames(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        return
    for order in "<>":
        magic, = struct.unpack(order + "I", data[:4])
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            break
    else:
        return  # pcapng or compressed: not read here
    linktype = struct.unpack(order + "I", data[20:24])[0] & 0xFFFF
    at = 24
    while at + 16 <= len(data):
        caplen, = struct.unpack(order + "I", data[at + 8:at + 12])
        yield linktype, data[at + 16:at + 16 + caplen]
        at += 16 + caplen


def save(target, data):
    d = os.path.join(ROOT, "fuzz", "corpus", target)
    os.makedirs(d, exist_ok=True)
    name = hashlib.sha1(data).hexdigest()
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def main():
    tcpflow = sys.argv[1]
    captures = sorted(glob.glob(os.path.join(ROOT, "tests", "captures", "*", "*.pcap*")))
    for path in captures:
        for linktype, frame in frames(path):
            if linktype in LINKTYPES:
                save("decode", bytes([LINKTYPES.index(linktype)]) + frame)
    for path in captures:
        if "/http/" not in path and "/ipv6/" not in path:
            continue
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([tcpflow, "-o", out, "-r", path], check=True,
                           stderr=subprocess.DEVNULL)
            for flow in glob.glob(os.path.join(out, "*")):
                if os.path.isfile(flow):
                    data = open(flow, "rb").read()
                    if data.startswith(b"HTTP/1."):
                        save("http", b"\0" + data)


if __name__ == "__main__":
    main()
