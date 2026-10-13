#!/usr/bin/env python3
"""Minimal DNS server for tests: answers A, AAAA and SRV queries from a JSON zone file.

    python3 tests/dns_server.py PORT ZONE.json

The zone file is re-read on every query, so tests change records by rewriting it:

    {
      "backends.test":            {"A": ["127.0.0.1", "127.0.0.2"]},
      "_http._tcp.svc.test":      {"SRV": [[10, 1, 9701, "a.test"], [10, 3, 9702, "b.test"]]},
      "a.test":                   {"A": ["127.0.0.1"]}
    }

SRV entries are [priority, weight, port, target]. Names are matched case-insensitively,
without the trailing dot. Unknown names get NXDOMAIN; a known name without the
requested type gets an empty NOERROR answer. Only UDP is served.
"""
import json
import socket
import struct
import sys

PORT = int(sys.argv[1])
ZONE = sys.argv[2]
TTL = 1


def read_name(msg, off):
    labels = []
    while True:
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            sub, _ = read_name(msg, ptr)
            labels.append(sub)
            off += 2
            break
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(l for l in labels if l), off


def encode_name(name):
    out = b""
    for label in name.strip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def load_zone():
    try:
        with open(ZONE) as f:
            z = json.load(f)
    except Exception:
        z = {}
    return {k.lower().rstrip("."): v for k, v in z.items()}


def answer(msg):
    (ident, flags, qd, an, ns, ar) = struct.unpack("!HHHHHH", msg[:12])
    qname, off = read_name(msg, 12)
    qtype, qclass = struct.unpack("!HH", msg[off:off + 4])
    question = msg[12:off + 4]
    zone = load_zone()
    rec = zone.get(qname.lower())
    rcode = 0 if rec is not None else 3
    answers = b""
    count = 0
    if rec is not None:
        if qtype == 1:
            for ip in rec.get("A", []):
                answers += encode_name(qname) + struct.pack("!HHIH", 1, 1, TTL, 4) + socket.inet_aton(ip)
                count += 1
        elif qtype == 28:
            for ip in rec.get("AAAA", []):
                answers += encode_name(qname) + struct.pack("!HHIH", 28, 1, TTL, 16) + socket.inet_pton(socket.AF_INET6, ip)
                count += 1
        elif qtype == 33:
            for prio, weight, port, target in rec.get("SRV", []):
                rdata = struct.pack("!HHH", prio, weight, port) + encode_name(target)
                answers += encode_name(qname) + struct.pack("!HHIH", 33, 1, TTL, len(rdata)) + rdata
                count += 1
    hdr = struct.pack("!HHHHHH", ident, 0x8180 | rcode, 1, count, 0, 0)
    return hdr + question + answers


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    while True:
        try:
            msg, peer = s.recvfrom(4096)
            if len(msg) < 12:
                continue
            s.sendto(answer(msg), peer)
        except KeyboardInterrupt:
            return
        except Exception:
            continue


if __name__ == "__main__":
    main()
