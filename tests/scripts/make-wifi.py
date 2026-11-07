"""Make the 802.11 test captures from an Ethernet capture (SPEC.md 4.1).

    python3 -I tests/scripts/make-wifi.py tests/captures/http/two-connections.pcap tests/captures/link

Every frame becomes an 802.11 data frame with LLC/SNAP and a valid FCS:

    wifi-80211.pcap     DLT_IEEE802_11 (105), ad hoc (no DS bits)
    wifi-radiotap.pcap  DLT_IEEE802_11_RADIO (127), QoS data, to or from the AP;
                        radiotap with TSFT, flags (FCS present) and rate
    wifi-prism.pcap     DLT_PRISM_HEADER (119), WDS (four addresses)
"""

import os
import struct
import sys
import zlib

BSSID = bytes.fromhex("020000000001")


def read_pcap(path):
    data = open(path, "rb").read()
    magic, = struct.unpack("<I", data[:4])
    assert magic == 0xA1B2C3D4, "a little-endian classic pcap is expected"
    assert struct.unpack("<I", data[20:24])[0] == 1, "Ethernet is expected"
    at = 24
    while at < len(data):
        secs, usecs, caplen, length = struct.unpack("<IIII", data[at:at + 16])
        yield secs, usecs, length, data[at + 16:at + 16 + caplen]
        at += 16 + caplen


def wifi(kind, frame, from_client):
    da, sa, ethertype, body = frame[0:6], frame[6:12], frame[12:14], frame[14:]
    seq = b"\x00\x00"
    if kind == "ibss":
        header = b"\x08\x00" + b"\x00\x00" + da + sa + BSSID + seq
    elif kind == "qos":
        if from_client:
            header = b"\x88\x01" + b"\x00\x00" + BSSID + sa + da + seq
        else:
            header = b"\x88\x02" + b"\x00\x00" + da + BSSID + sa + seq
        header += b"\x00\x00"  # QoS control
    else:  # wds
        header = b"\x08\x03" + b"\x00\x00" + BSSID + BSSID + da + seq + sa
    mpdu = header + b"\xaa\xaa\x03\x00\x00\x00" + ethertype + body
    return mpdu + struct.pack("<I", zlib.crc32(mpdu))


RADIOTAP = struct.pack("<BBHI", 0, 0, 18, 0b111) + struct.pack("<QBB", 0, 0x10, 2)
PRISM = struct.pack("<II", 0x41, 144) + b"wlan0".ljust(16, b"\x00") + bytes(120)

KINDS = [
    ("wifi-80211.pcap", 105, "ibss", b""),
    ("wifi-radiotap.pcap", 127, "qos", RADIOTAP),
    ("wifi-prism.pcap", 119, "wds", PRISM),
]


def main(src, outdir):
    packets = list(read_pcap(src))
    client = packets[0][3][6:12]
    for name, linktype, kind, prefix in KINDS:
        with open(os.path.join(outdir, name), "wb") as out:
            out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
            for secs, usecs, length, frame in packets:
                f = prefix + wifi(kind, frame, frame[6:12] == client)
                extra = len(f) - len(frame)
                out.write(struct.pack("<IIII", secs, usecs, len(f), length + extra))
                out.write(f)


if __name__ == "__main__":
    main(*sys.argv[1:])
