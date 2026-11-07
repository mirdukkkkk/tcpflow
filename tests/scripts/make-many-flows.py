"""Make a capture with many concurrent flows, to measure tcpflow's speed.

    python3 -I tests/scripts/make-many-flows.py FLOWS ROUNDS OUT.pcap

Every flow is a client on 10.x.y.z talking to 192.168.0.1:80. The first
round sends a SYN for every flow, each following round sends one 100-byte
data segment for every flow, and the last round sends a FIN for every flow.
All flows are open at the same time. Packets are 1 ms apart.
"""

import struct
import sys

SERVER = bytes([192, 168, 0, 1])
MAC_C = bytes.fromhex("020000000001")
MAC_S = bytes.fromhex("020000000002")
PAYLOAD = b"x" * 100


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(n, seq, flags, payload):
    client = bytes([10, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    sport = 1024 + n % 60000
    tcp = struct.pack("!HHIIBBHHH", sport, 80, seq, 0, 5 << 4, flags, 65535, 0, 0)
    pseudo = client + SERVER + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    csum = checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0, client, SERVER)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return MAC_S + MAC_C + b"\x08\x00" + ip + tcp + payload


def main():
    flows, rounds, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        t = 0
        for r in range(rounds + 2):
            for n in range(flows):
                if r == 0:
                    data = frame(n, 1000, 0x02, b"")  # SYN
                elif r <= rounds:
                    data = frame(n, 1001 + (r - 1) * len(PAYLOAD), 0x18, PAYLOAD)
                else:
                    data = frame(n, 1001 + rounds * len(PAYLOAD), 0x11, b"")  # FIN
                f.write(struct.pack("<IIII", t // 1000, t % 1000 * 1000, len(data), len(data)))
                f.write(data)
                t += 1


if __name__ == "__main__":
    main()
