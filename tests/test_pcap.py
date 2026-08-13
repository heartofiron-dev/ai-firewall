import struct
import tempfile
import unittest
from pathlib import Path

from ai_firewall.pcap import read_capture, read_pcap


def ethernet_ipv4_tcp(
    src: bytes = bytes([10, 0, 0, 5]),
    dst: bytes = bytes([192, 168, 1, 10]),
    src_port: int = 50000,
    dst_port: int = 443,
    flags: int = 0x02,
) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, src, dst
    )
    tcp_header = struct.pack(
        "!HHLLBBHHH", src_port, dst_port, 0, 0, 5 << 4, flags, 1024, 0, 0
    )
    return ethernet + ip_header + tcp_header


def classic_pcap(frames: list[bytes]) -> bytes:
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        data.extend(struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)))
        data.extend(frame)
    return bytes(data)


def pcapng_block(block_type: int, body: bytes) -> bytes:
    if len(body) % 4:
        raise ValueError("test block body must be padded")
    total_length = 12 + len(body)
    return struct.pack("<II", block_type, total_length) + body + struct.pack("<I", total_length)


def pcapng_capture(frame: bytes) -> bytes:
    section = pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    ts_resolution = struct.pack("<HH", 9, 1) + b"\x06\x00\x00\x00"
    end_options = struct.pack("<HH", 0, 0)
    interface = pcapng_block(1, struct.pack("<HHI", 1, 0, 65535) + ts_resolution + end_options)
    timestamp = 1_700_000_000 * 1_000_000
    padded_frame = frame + b"\x00" * ((-len(frame)) % 4)
    enhanced = pcapng_block(
        6,
        struct.pack(
            "<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF,
            len(frame), len(frame),
        ) + padded_frame,
    )
    return section + interface + enhanced


class PcapTests(unittest.TestCase):
    def test_parses_and_aggregates_tcp_flows(self):
        payload = classic_pcap([
            ethernet_ipv4_tcp(dst_port=22),
            ethernet_ipv4_tcp(dst_port=23),
        ])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pcap"
            path.write_bytes(payload)
            flows = read_pcap(path)
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[0].src_ip, "10.0.0.5")
        self.assertEqual(flows[0].protocol, "TCP")
        self.assertEqual(flows[1].unique_dst_ports_60s, 2)
        self.assertEqual(flows[1].connections_60s, 2)

    def test_merges_reverse_packets_and_counts_bytes(self):
        client = bytes([10, 0, 0, 5])
        server = bytes([192, 168, 1, 10])
        payload = classic_pcap([
            ethernet_ipv4_tcp(client, server, 50000, 443, 0x02),
            ethernet_ipv4_tcp(server, client, 443, 50000, 0x12),
        ])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "roundtrip.pcap"
            path.write_bytes(payload)
            merged = read_pcap(path)
            directional = read_pcap(path, bidirectional=False)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].packets, 2)
        self.assertEqual(merged[0].bytes_sent, 40)
        self.assertEqual(merged[0].bytes_received, 40)
        self.assertEqual(len(directional), 2)

    def test_auto_detects_pcapng_and_interface_resolution(self):
        payload = pcapng_capture(ethernet_ipv4_tcp(dst_port=443))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pcapng"
            path.write_bytes(payload)
            flows = read_capture(path)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].timestamp, "2023-11-14T22:13:20Z")
        self.assertEqual(flows[0].bytes_sent, 40)

    def test_rejects_unknown_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.capture"
            path.write_bytes(b"not a capture")
            with self.assertRaisesRegex(ValueError, "classic PCAP"):
                read_capture(path)


if __name__ == "__main__":
    unittest.main()

