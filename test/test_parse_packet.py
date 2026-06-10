import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.logic import parse_packet


def _make_pxe_request():
    # Build minimal BOOTREQUEST with PXE option (option 60)
    pkt = bytearray(240)
    pkt[0] = 1  # BOOTREQUEST
    pkt[4:8] = b"\x01\x02\x03\x04"  # transaction id
    pkt[28:34] = b"\xaa\xbb\xcc\xdd\xee\xff"  # client MAC
    pkt[236:240] = b"\x63\x82\x53\x63"  # DHCP magic cookie
    # options: tag 60 (len 9) = b'PXEClient', end(255)
    pkt += bytes([60, 9]) + b"PXEClient"
    pkt += bytes([255])
    return bytes(pkt)


def test_parse_packet_detects_pxe():
    data = _make_pxe_request()
    addr = ("127.0.0.1", 4011)
    info = parse_packet(data, addr)
    assert info is not None
    assert info["client_address"] == addr
    assert info["transaction_id"] == b"\x01\x02\x03\x04"
    assert info["mac_readable"] == "aa:bb:cc:dd:ee:ff"
