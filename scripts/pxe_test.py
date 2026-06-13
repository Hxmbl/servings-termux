#!/usr/bin/env python3
"""PXE test harness — simulates a full PXE client boot sequence.

Sends real DHCP/PXE, TFTP, and HTTP requests to a servings server and
analyses every response. Useful for verifying servings works without
needing a physical PXE-bootable machine.

Usage:
  python3 scripts/pxe_test.py 192.168.1.62          # test a remote servings
  python3 scripts/pxe_test.py 127.0.0.1              # test local servings
  python3 scripts/pxe_test.py 192.168.1.62 --dump    # verbose hex dump
"""

import argparse
import random
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


# ── Constants ──────────────────────────────────────────────────────────

MAGIC_COOKIE = b"\x63\x82\x53\x63"
TFTP_RRQ = 1
TFTP_DATA = 3
TFTP_ACK = 4
TFTP_ERROR = 5
TFTP_BLOCK_SIZE = 512

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5

PXE_PORT = 4011
TFTP_PORT = 6969
HTTP_PORT = 8080

OPT_PAD = 0
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_DOMAIN = 15
OPT_IP_LEASE_TIME = 51
OPT_MESSAGE_TYPE = 53
OPT_SERVER_ID = 54
OPT_VENDOR_CLASS = 60
OPT_TFTP_SERVER = 66
OPT_BOOT_FILE = 67
OPT_END = 255


# ── Data ───────────────────────────────────────────────────────────────

@dataclass
class PxeResult:
    proxy_addr: tuple | None = None
    proxy_latency: float = 0.0
    proxy_opts: dict = field(default_factory=dict)
    proxy_raw: bytes = field(default_factory=bytes)

    tftp_addr: tuple | None = None
    tftp_latency: float = 0.0
    tftp_size: int = 0
    tftp_blocks: int = 0

    http_addr: tuple | None = None
    http_latency: float = 0.0
    http_status: int = 0
    http_size: int = 0
    http_body: str = ""


# ── Packet builders ───────────────────────────────────────────────────

def build_dhcp_discover(mac: bytes, xid: bytes | None = None) -> bytes:
    xid = xid or random.getrandbits(32).to_bytes(4, "big")
    header = struct.pack(
        "!BBBB4sHH4s4s4s4s16s64s128s",
        1, 1, 6, 0, xid, 0, 0,
        b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,
        mac + b"\x00" * 10,
        b"\x00" * 64, b"\x00" * 128,
    )
    opts = (
        MAGIC_COOKIE
        + bytes([OPT_MESSAGE_TYPE, 1, DHCP_DISCOVER])
        + bytes([OPT_VENDOR_CLASS, 9]) + b"PXEClient"
        + bytes([OPT_END])
    )
    return header + opts


def build_dhcp_request(mac: bytes, xid: bytes, server_ip: str, requested_ip: str) -> bytes:
    ciaddr = socket.inet_aton("0.0.0.0")
    opts = (
        MAGIC_COOKIE
        + bytes([OPT_MESSAGE_TYPE, 1, DHCP_REQUEST])
        + bytes([OPT_SERVER_ID, 4]) + socket.inet_aton(server_ip)
        + bytes([50, 4]) + socket.inet_aton(requested_ip)
        + bytes([OPT_VENDOR_CLASS, 9]) + b"PXEClient"
        + bytes([OPT_END])
    )
    header = struct.pack(
        "!BBBB4sHH4s4s4s4s16s64s128s",
        1, 1, 6, 0, xid, 0, 0,
        ciaddr, socket.inet_aton("0.0.0.0"),
        socket.inet_aton("0.0.0.0"), socket.inet_aton("0.0.0.0"),
        mac + b"\x00" * 10,
        b"\x00" * 64, b"\x00" * 128,
    )
    return header + opts


def build_tftp_rrq(filename: str) -> bytes:
    return struct.pack("!H", TFTP_RRQ) + filename.encode() + b"\x00octet\x00"


def build_tftp_ack(block_num: int) -> bytes:
    return struct.pack("!HH", TFTP_ACK, block_num)


# ── Parsers ───────────────────────────────────────────────────────────

def parse_dhcp_opts(data: bytes) -> dict:
    """Walk DHCP options and return a dict of tag->value."""
    opts = {}
    if data[236:240] != MAGIC_COOKIE:
        return opts
    cursor = 240
    while cursor < len(data):
        tag = data[cursor]
        if tag == OPT_END:
            break
        if cursor + 1 >= len(data):
            break
        length = data[cursor + 1]
        value = data[cursor + 2 : cursor + 2 + length]
        opts[tag] = value
        cursor += 2 + length
    return opts


def describe_opts(opts: dict) -> list[str]:
    lines = []
    for tag, val in sorted(opts.items()):
        name = {
            OPT_MESSAGE_TYPE: "msg-type",
            OPT_SERVER_ID: "server-id",
            OPT_SUBNET_MASK: "subnet-mask",
            OPT_ROUTER: "router",
            OPT_DNS: "dns",
            OPT_DOMAIN: "domain",
            OPT_IP_LEASE_TIME: "lease-time",
            OPT_TFTP_SERVER: "tftp-server",
            OPT_BOOT_FILE: "boot-file",
            OPT_VENDOR_CLASS: "vendor-class",
            50: "requested-ip",
        }.get(tag, f"opt-{tag}")
        if tag == OPT_MESSAGE_TYPE:
            lines.append(f"    {name} = {val[0]} ({['?', 'DISCOVER', 'OFFER', 'REQUEST', '?', 'ACK'][val[0]]})")
        elif tag in (OPT_IP_LEASE_TIME,):
            lines.append(f"    {name} = {int.from_bytes(val, 'big')}s")
        elif tag in (OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_SERVER_ID, OPT_TFTP_SERVER, 50):
            lines.append(f"    {name} = {socket.inet_ntoa(val[:4])}")
        elif tag == OPT_BOOT_FILE:
            lines.append(f"    {name} = {val.rstrip(b'\\x00').decode(errors='replace')}")
        elif tag == OPT_VENDOR_CLASS:
            lines.append(f"    {name} = {val.decode(errors='replace')}")
        else:
            lines.append(f"    {name} = {val.hex()}")
    return lines


# ── Test steps ────────────────────────────────────────────────────────

def test_proxydhcp(host: str, port: int, mac: bytes, dump: bool) -> PxeResult:
    result = PxeResult()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5.0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    pkt = build_dhcp_discover(mac)

    t0 = time.perf_counter()
    s.sendto(pkt, (host, port))

    try:
        data, addr = s.recvfrom(4096)
        result.proxy_latency = time.perf_counter() - t0
        result.proxy_addr = addr
        result.proxy_raw = data
        result.proxy_opts = parse_dhcp_opts(data)
    except socket.timeout:
        pass

    s.close()
    return result


def test_tftp(host: str, port: int, filename: str, dump: bool) -> PxeResult:
    result = PxeResult()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5.0)
    s.bind(("0.0.0.0", 0))

    pkt = build_tftp_rrq(filename)
    t0 = time.perf_counter()
    s.sendto(pkt, (host, port))

    received = bytearray()
    expected_block = 1
    addr = None

    try:
        while True:
            data, addr = s.recvfrom(2048)
            opcode = struct.unpack("!H", data[:2])[0]
            if opcode == TFTP_ERROR:
                errcode = struct.unpack("!H", data[2:4])[0]
                errmsg = data[4:].rstrip(b"\x00").decode(errors="replace")
                print(f"  [!] TFTP error {errcode}: {errmsg}")
                break
            elif opcode == TFTP_DATA:
                block = struct.unpack("!H", data[2:4])[0]
                payload = data[4:]
                received.extend(payload)
                s.sendto(build_tftp_ack(block), addr)

                if block != expected_block:
                    print(f"  [!] TFTP out-of-order block: expected {expected_block}, got {block}")
                    break

                expected_block += 1
                if len(payload) < TFTP_BLOCK_SIZE:
                    break
    except socket.timeout:
        pass

    result.tftp_latency = time.perf_counter() - t0
    result.tftp_addr = addr
    result.tftp_size = len(received)
    result.tftp_blocks = expected_block - 1

    s.close()
    return result


def test_http(host: str, port: int, path: str, dump: bool) -> PxeResult:
    import http.client
    result = PxeResult()
    t0 = time.perf_counter()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        result.http_latency = time.perf_counter() - t0
        result.http_status = resp.status
        body = resp.read()
        result.http_size = len(body)
        result.http_body = body.decode(errors="replace")
        result.http_addr = (host, port)
        conn.close()
    except Exception as e:
        print(f"  [!] HTTP error: {e}")
    return result


# ── Reporter ──────────────────────────────────────────────────────────

def report(r: PxeResult, dump: bool):
    print()
    print("=" * 60)
    print("  PXE Test Results")
    print("=" * 60)

    # ProxyDHCP
    print(f"\n  ── 1. ProxyDHCP (UDP {PXE_PORT}) ──")
    if r.proxy_addr:
        print(f"  Reply from   : {r.proxy_addr[0]}:{r.proxy_addr[1]}")
        print(f"  Latency      : {r.proxy_latency*1000:.1f} ms")
        print(f"  Reply size   : {len(r.proxy_raw)} bytes")
        print(f"  Options parsed:")
        for line in describe_opts(r.proxy_opts):
            print(line)
        msg_type = r.proxy_opts.get(OPT_MESSAGE_TYPE, [b"?"])[0]
        if msg_type == DHCP_ACK:
            print(f"  ✓ PXE handshake complete")
        else:
            print(f"  ⚠ Expected ACK (5), got {msg_type}")
    else:
        print(f"  ✗ No reply (timeout) — PXE server may be unreachable")

    # TFTP
    print(f"\n  ── 2. TFTP (UDP {TFTP_PORT}) ──")
    if r.tftp_size > 0:
        print(f"  From         : {r.tftp_addr}")
        print(f"  Latency      : {r.tftp_latency*1000:.1f} ms")
        print(f"  File         : {r.tftp_size} bytes in {r.tftp_blocks} blocks")
        rate = r.tftp_size / r.tftp_latency / 1024 if r.tftp_latency > 0 else 0
        print(f"  Throughput   : {rate:.0f} KB/s")
        print(f"  ✓ TFTP transfer complete")
    else:
        print(f"  ✗ No data received")

    # HTTP
    print(f"\n  ── 3. HTTP (TCP {HTTP_PORT}) ──")
    if r.http_status:
        print(f"  From         : {r.http_addr}")
        print(f"  Latency      : {r.http_latency*1000:.1f} ms")
        print(f"  Status       : {r.http_status}")
        print(f"  Body size    : {r.http_size} bytes")
        if r.http_status == 200:
            print(f"  ✓ HTTP request successful")
            if r.http_size < 2000:
                print(f"  Body preview : {r.http_body.strip()[:200]}")
        else:
            print(f"  ⚠ Unexpected status")
    else:
        print(f"  ✗ No response")

    print()
    if r.proxy_addr and r.tftp_size > 0 and r.http_status == 200:
        print(f"  ✅ Full PXE chain verified!")
    else:
        print(f"  ⚠ Chain incomplete")

    if dump:
        print(f"\n  ── Raw ProxyDHCP reply (hex) ──")
        if r.proxy_raw:
            for i in range(0, len(r.proxy_raw), 16):
                hex_part = " ".join(f"{b:02x}" for b in r.proxy_raw[i:i+16])
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in r.proxy_raw[i:i+16])
                print(f"  {i:04x}  {hex_part:<48s}  {ascii_part}")
    print()


# ── Main ──────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="PXE test harness — simulates a full PXE client boot")
    p.add_argument("host", nargs="?", default="127.0.0.1", help="servings server IP")
    p.add_argument("--pxe-port", type=int, default=PXE_PORT, help="ProxyDHCP port")
    p.add_argument("--tftp-port", type=int, default=TFTP_PORT, help="TFTP port")
    p.add_argument("--http-port", type=int, default=HTTP_PORT, help="HTTP port")
    p.add_argument("--mac", default="de:ad:be:ef:ca:fe", help="fake client MAC")
    p.add_argument("--dump", action="store_true", help="hex dump raw packets")
    p.add_argument("--bootloader", default="undionly.kpxe", help="bootloader filename")
    args = p.parse_args()

    try:
        mac_bytes = bytes(int(x, 16) for x in args.mac.split(":"))
    except ValueError:
        print(f"[!] Invalid MAC: {args.mac}")
        sys.exit(1)

    print(f"  Target       : {args.host}")
    print(f"  Client MAC   : {args.mac}")

    r = PxeResult()

    pdhcp = test_proxydhcp(args.host, args.pxe_port, mac_bytes, args.dump)
    r.proxy_addr = pdhcp.proxy_addr
    r.proxy_latency = pdhcp.proxy_latency
    r.proxy_opts = pdhcp.proxy_opts
    r.proxy_raw = pdhcp.proxy_raw

    tftp = test_tftp(args.host, args.tftp_port, args.bootloader, args.dump)
    r.tftp_addr = tftp.tftp_addr
    r.tftp_latency = tftp.tftp_latency
    r.tftp_size = tftp.tftp_size
    r.tftp_blocks = tftp.tftp_blocks

    http = test_http(args.host, args.http_port, "/boot.cfg", args.dump)
    r.http_addr = http.http_addr
    r.http_latency = http.http_latency
    r.http_status = http.http_status
    r.http_size = http.http_size
    r.http_body = http.http_body

    report(r, args.dump)


if __name__ == "__main__":
    main()
