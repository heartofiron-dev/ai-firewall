import struct
import tempfile
import unittest
from pathlib import Path

from ai_firewall.pcap import read_pcap


def ethernet_ipv4_tcp(dst_port: int, flags: int = 0x02) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    src = bytes([10, 0, 0, 5])
    dst = bytes([192, 168, 1, 10])
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, src, dst
    )
    tcp_header = struct.pack("!HHLLBBHHH", 50000, dst_port, 0, 0, 5 << 4, flags, 1024, 0, 0)
    return ethernet + ip_header + tcp_header


def classic_pcap(frames: list[bytes]) -> bytes:
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        data.extend(struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)))
        data.extend(frame)
    return bytes(data)


class PcapTests(unittest.TestCase):
    def test_parses_and_aggregates_tcp_flows(self):
        payload = classic_pcap([
            ethernet_ipv4_tcp(22),
            ethernet_ipv4_tcp(23),
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

    def test_rejects_unknown_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.pcap"
            path.write_bytes(b"not a pcap")
            with self.assertRaisesRegex(ValueError, "classic PCAP"):
                read_pcap(path)


if __name__ == "__main__":
    unittest.main()

