from __future__ import annotations

import ipaddress
import struct
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .schema import FlowRecord


@dataclass
class _FlowAccumulator:
    first_seen: float
    last_seen: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: int = 0
    bytes_sent: int = 0
    syn_count: int = 0
    rst_count: int = 0


def _transport_from_ip(packet: bytes) -> tuple[str, str, int, int, str, int, int, int] | None:
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20:
            return None
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl:
            return None
        total_length = min(struct.unpack("!H", packet[2:4])[0], len(packet))
        protocol_number = packet[9]
        fragment_offset = struct.unpack("!H", packet[6:8])[0] & 0x1FFF
        if fragment_offset:
            return None
        src_ip = str(ipaddress.ip_address(packet[12:16]))
        dst_ip = str(ipaddress.ip_address(packet[16:20]))
        transport = packet[ihl:total_length]
    elif version == 6:
        if len(packet) < 40:
            return None
        protocol_number = packet[6]
        # Extension headers are deliberately skipped in v0.2 instead of guessed.
        if protocol_number not in {6, 17}:
            return None
        payload_length = struct.unpack("!H", packet[4:6])[0]
        total_length = min(40 + payload_length, len(packet))
        src_ip = str(ipaddress.ip_address(packet[8:24]))
        dst_ip = str(ipaddress.ip_address(packet[24:40]))
        transport = packet[40:total_length]
    else:
        return None

    if protocol_number == 6 and len(transport) >= 20:
        src_port, dst_port = struct.unpack("!HH", transport[:4])
        flags = transport[13]
        return src_ip, dst_ip, src_port, dst_port, "TCP", total_length, int(bool(flags & 0x02)), int(bool(flags & 0x04))
    if protocol_number == 17 and len(transport) >= 8:
        src_port, dst_port = struct.unpack("!HH", transport[:4])
        return src_ip, dst_ip, src_port, dst_port, "UDP", total_length, 0, 0
    return None


def _network_packet(frame: bytes, link_type: int) -> bytes | None:
    if link_type == 1:  # Ethernet
        if len(frame) < 14:
            return None
        offset = 14
        ether_type = struct.unpack("!H", frame[12:14])[0]
        while ether_type in {0x8100, 0x88A8}:
            if len(frame) < offset + 4:
                return None
            ether_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
        if ether_type not in {0x0800, 0x86DD}:
            return None
        return frame[offset:]
    if link_type == 101:  # Raw IPv4/IPv6
        return frame
    if link_type == 113:  # Linux cooked capture v1
        if len(frame) < 16:
            return None
        protocol = struct.unpack("!H", frame[14:16])[0]
        return frame[16:] if protocol in {0x0800, 0x86DD} else None
    raise ValueError(f"暂不支持 PCAP link type {link_type}；当前支持 Ethernet(1)、RAW(101)、Linux SLL(113)")


def _iso_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def read_pcap(path: str | Path, max_packets: int | None = None) -> list[FlowRecord]:
    """Parse a classic PCAP file and aggregate directional five-tuple flows."""
    magic_formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
    }
    accumulators: dict[tuple[str, str, int, int, str], _FlowAccumulator] = {}

    with Path(path).open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24 or header[:4] not in magic_formats:
            raise ValueError("不是受支持的 classic PCAP 文件（PCAPNG 将在后续版本支持）")
        endian, fraction_scale = magic_formats[header[:4]]
        major, minor, _zone, _sigfigs, _snaplen, link_type = struct.unpack(endian + "HHiIII", header[4:])
        if major != 2 or minor != 4:
            raise ValueError(f"不支持的 PCAP 版本 {major}.{minor}")

        packet_count = 0
        while max_packets is None or packet_count < max_packets:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("PCAP 数据包头被截断")
            seconds, fraction, included_length, _original_length = struct.unpack(endian + "IIII", packet_header)
            if included_length > 64 * 1024 * 1024:
                raise ValueError("PCAP 数据包长度异常，已停止解析")
            frame = handle.read(included_length)
            if len(frame) != included_length:
                raise ValueError("PCAP 数据包内容被截断")
            packet_count += 1
            network = _network_packet(frame, link_type)
            decoded = _transport_from_ip(network or b"")
            if decoded is None:
                continue
            src_ip, dst_ip, src_port, dst_port, protocol, byte_count, syn, rst = decoded
            timestamp = seconds + fraction / fraction_scale
            key = (src_ip, dst_ip, src_port, dst_port, protocol)
            accumulator = accumulators.get(key)
            if accumulator is None:
                accumulator = _FlowAccumulator(timestamp, timestamp, *key)
                accumulators[key] = accumulator
            accumulator.last_seen = timestamp
            accumulator.packets += 1
            accumulator.bytes_sent += byte_count
            accumulator.syn_count += syn
            accumulator.rst_count += rst

    ordered = sorted(accumulators.values(), key=lambda item: item.first_seen)
    recent_by_source: dict[str, deque[_FlowAccumulator]] = defaultdict(deque)
    records: list[FlowRecord] = []
    for accumulator in ordered:
        recent = recent_by_source[accumulator.src_ip]
        while recent and recent[0].first_seen < accumulator.first_seen - 60:
            recent.popleft()
        recent.append(accumulator)
        records.append(FlowRecord(
            timestamp=_iso_timestamp(accumulator.first_seen),
            src_ip=accumulator.src_ip,
            dst_ip=accumulator.dst_ip,
            src_port=accumulator.src_port,
            dst_port=accumulator.dst_port,
            protocol=accumulator.protocol,
            duration_ms=max((accumulator.last_seen - accumulator.first_seen) * 1000, 0.0),
            packets=accumulator.packets,
            bytes_sent=accumulator.bytes_sent,
            bytes_received=0,
            syn_count=accumulator.syn_count,
            rst_count=accumulator.rst_count,
            unique_dst_ports_60s=len({item.dst_port for item in recent}),
            connections_60s=len(recent),
            failed_connections_60s=sum(item.rst_count > 0 for item in recent),
        ))
    return records

