from __future__ import annotations

import ipaddress
import json
import math
import socket
import threading
import time
from contextlib import ExitStack, closing
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from .detector import HybridDetector
from .schema import FlowRecord


LOOPBACK = "127.0.0.1"
LAB_CONFIRMATION = "LOCAL-LAB"
SCENARIOS = (
    "normal",
    "port-scan",
    "brute-force",
    "connection-flood",
    "data-spike",
    "suspicious-port",
)
PORT_SCAN_CONNECTIONS = 20
BRUTE_FORCE_ATTEMPTS = 12
FLOOD_CONNECTIONS = 220
DATA_SPIKE_BYTES = 50_500_000
AUTH_PORTS = (5900, 23, 21, 22, 445, 3389)
SUSPICIOUS_PORTS = (4444, 5555, 6667, 31337)
SOCKET_TIMEOUT_SECONDS = 4.0


@dataclass(frozen=True)
class LabObservation:
    scenario: str
    description: str
    expected_rule: str | None
    flow: FlowRecord
    measurements: dict[str, object]


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _flow(
    *,
    src_port: int,
    dst_port: int,
    duration_ms: float,
    packets: int,
    bytes_sent: int,
    bytes_received: int,
    syn_count: int,
    rst_count: int = 0,
    unique_dst_ports_60s: int = 1,
    connections_60s: int = 1,
    failed_connections_60s: int = 0,
    label: str,
) -> FlowRecord:
    return FlowRecord(
        timestamp=_timestamp(),
        src_ip=LOOPBACK,
        dst_ip=LOOPBACK,
        src_port=src_port,
        dst_port=dst_port,
        protocol="TCP",
        duration_ms=max(duration_ms, 0.001),
        packets=max(packets, 1),
        bytes_sent=max(bytes_sent, 0),
        bytes_received=max(bytes_received, 0),
        syn_count=max(syn_count, 0),
        rst_count=max(rst_count, 0),
        unique_dst_ports_60s=max(unique_dst_ports_60s, 0),
        connections_60s=max(connections_60s, 0),
        failed_connections_60s=max(failed_connections_60s, 0),
        label=label,
    )


def _listener(port: int = 0) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.settimeout(SOCKET_TIMEOUT_SECONDS)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind((LOOPBACK, port))
        listener.listen(256)
        address, _ = listener.getsockname()
        if address != LOOPBACK:
            raise OSError("本机实验监听器未绑定到固定 loopback 地址")
        return listener
    except Exception:
        listener.close()
        raise


def _first_available_listener(ports: tuple[int, ...]) -> socket.socket:
    failures = []
    for port in ports:
        try:
            return _listener(port)
        except OSError as exc:
            failures.append(f"{port}: {exc}")
    raise OSError("本机实验端口均不可用；未连接任何现有服务（" + "; ".join(failures) + "）")


def _connect_owned(listener: socket.socket) -> tuple[socket.socket, socket.socket]:
    address, port = listener.getsockname()
    if address != LOOPBACK or not ipaddress.ip_address(address).is_loopback:
        raise OSError("拒绝连接非 loopback 实验监听器")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.settimeout(SOCKET_TIMEOUT_SECONDS)
        client.connect((LOOPBACK, int(port)))
        accepted, peer = listener.accept()
        accepted.settimeout(SOCKET_TIMEOUT_SECONDS)
        if peer[0] != LOOPBACK or client.getpeername()[0] != LOOPBACK:
            accepted.close()
            raise OSError("本机实验连接离开了 loopback")
        return client, accepted
    except Exception:
        client.close()
        raise


def _elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000.0


def run_normal_socket_scenario() -> LabObservation:
    request = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
    response = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    started = time.perf_counter()
    with closing(_listener()) as listener:
        destination_port = int(listener.getsockname()[1])
        client, server = _connect_owned(listener)
        with closing(client), closing(server):
            source_port = int(client.getsockname()[1])
            client.sendall(request)
            received_request = server.recv(4096)
            server.sendall(response)
            received_response = client.recv(4096)
    return LabObservation(
        scenario="normal",
        description="本机临时 HTTP 服务的一次正常请求",
        expected_rule=None,
        flow=_flow(
            src_port=source_port,
            dst_port=destination_port,
            duration_ms=_elapsed_ms(started),
            packets=8,
            bytes_sent=len(received_request),
            bytes_received=len(received_response),
            syn_count=1,
            label="benign",
        ),
        measurements={
            "connections": 1,
            "request_bytes": len(received_request),
            "response_bytes": len(received_response),
            "owned_destination_ports": [destination_port],
        },
    )


def run_port_scan_socket_scenario() -> LabObservation:
    started = time.perf_counter()
    source_port = 0
    with ExitStack() as stack:
        listeners = [stack.enter_context(closing(_listener())) for _ in range(PORT_SCAN_CONNECTIONS)]
        ports = [int(item.getsockname()[1]) for item in listeners]
        if len(set(ports)) != PORT_SCAN_CONNECTIONS:
            raise OSError("未能创建足够的独占 loopback 测试端口")
        for listener in listeners:
            client, server = _connect_owned(listener)
            with closing(client), closing(server):
                if not source_port:
                    source_port = int(client.getsockname()[1])
    return LabObservation(
        scenario="port-scan",
        description="依次连接程序自己占用的 20 个本机临时端口",
        expected_rule="PORT_SCAN",
        flow=_flow(
            src_port=source_port,
            dst_port=ports[0],
            duration_ms=_elapsed_ms(started),
            packets=PORT_SCAN_CONNECTIONS * 3,
            bytes_sent=0,
            bytes_received=0,
            syn_count=PORT_SCAN_CONNECTIONS,
            unique_dst_ports_60s=PORT_SCAN_CONNECTIONS,
            connections_60s=PORT_SCAN_CONNECTIONS,
            label="attack",
        ),
        measurements={
            "connections": PORT_SCAN_CONNECTIONS,
            "unique_destination_ports": PORT_SCAN_CONNECTIONS,
            "owned_destination_ports": ports,
        },
    )


def run_brute_force_socket_scenario() -> LabObservation:
    request = b"AUTH local-lab fixed-invalid-token\n"
    response = b"DENIED\n"
    started = time.perf_counter()
    source_port = sent = received = 0
    with closing(_first_available_listener(AUTH_PORTS)) as listener:
        destination_port = int(listener.getsockname()[1])
        for _ in range(BRUTE_FORCE_ATTEMPTS):
            client, server = _connect_owned(listener)
            with closing(client), closing(server):
                if not source_port:
                    source_port = int(client.getsockname()[1])
                client.sendall(request)
                payload = server.recv(4096)
                server.sendall(response)
                reply = client.recv(4096)
                sent += len(payload)
                received += len(reply)
    return LabObservation(
        scenario="brute-force",
        description="本机虚拟认证服务拒绝 12 次固定测试令牌，不猜测真实密码",
        expected_rule="BRUTE_FORCE",
        flow=_flow(
            src_port=source_port,
            dst_port=destination_port,
            duration_ms=_elapsed_ms(started),
            packets=BRUTE_FORCE_ATTEMPTS * 8,
            bytes_sent=sent,
            bytes_received=received,
            syn_count=BRUTE_FORCE_ATTEMPTS,
            connections_60s=BRUTE_FORCE_ATTEMPTS,
            failed_connections_60s=BRUTE_FORCE_ATTEMPTS,
            label="attack",
        ),
        measurements={
            "connections": BRUTE_FORCE_ATTEMPTS,
            "dummy_auth_rejections": BRUTE_FORCE_ATTEMPTS,
            "credential_source": "fixed_non_secret_test_token",
            "owned_destination_ports": [destination_port],
        },
    )


def run_connection_flood_socket_scenario() -> LabObservation:
    started = time.perf_counter()
    source_port = 0
    with closing(_listener()) as listener:
        destination_port = int(listener.getsockname()[1])
        for _ in range(FLOOD_CONNECTIONS):
            client, server = _connect_owned(listener)
            with closing(client), closing(server):
                if not source_port:
                    source_port = int(client.getsockname()[1])
    return LabObservation(
        scenario="connection-flood",
        description="向一个本机临时服务建立 220 个有上限的短连接",
        expected_rule="CONNECTION_FLOOD",
        flow=_flow(
            src_port=source_port,
            dst_port=destination_port,
            duration_ms=_elapsed_ms(started),
            packets=FLOOD_CONNECTIONS * 3,
            bytes_sent=0,
            bytes_received=0,
            syn_count=FLOOD_CONNECTIONS,
            connections_60s=FLOOD_CONNECTIONS,
            label="attack",
        ),
        measurements={
            "connections": FLOOD_CONNECTIONS,
            "owned_destination_ports": [destination_port],
        },
    )


def run_data_spike_socket_scenario() -> LabObservation:
    started = time.perf_counter()
    with closing(_listener()) as listener:
        destination_port = int(listener.getsockname()[1])
        client, server = _connect_owned(listener)
        with closing(client), closing(server):
            source_port = int(client.getsockname()[1])
            received = 0
            receiver_error: list[BaseException] = []

            def drain() -> None:
                nonlocal received
                try:
                    while True:
                        chunk = server.recv(256 * 1024)
                        if not chunk:
                            break
                        received += len(chunk)
                except BaseException as exc:  # propagated after joining the bounded worker
                    receiver_error.append(exc)

            worker = threading.Thread(target=drain, name="ai-firewall-local-lab-drain", daemon=True)
            worker.start()
            block = b"L" * (256 * 1024)
            remaining = DATA_SPIKE_BYTES
            while remaining:
                piece = block if remaining >= len(block) else block[:remaining]
                client.sendall(piece)
                remaining -= len(piece)
            client.shutdown(socket.SHUT_WR)
            worker.join(timeout=SOCKET_TIMEOUT_SECONDS * 3)
            if worker.is_alive():
                raise OSError("本机数据突增接收线程超时")
            if receiver_error:
                raise OSError(f"本机数据突增接收失败: {receiver_error[0]}")
            if received != DATA_SPIKE_BYTES:
                raise OSError(f"本机数据突增字节不完整: {received}/{DATA_SPIKE_BYTES}")
    duration_ms = _elapsed_ms(started)
    return LabObservation(
        scenario="data-spike",
        description="向本机临时接收器传输固定上限 50.5 MB 内存数据",
        expected_rule="DATA_SPIKE",
        flow=_flow(
            src_port=source_port,
            dst_port=destination_port,
            duration_ms=duration_ms,
            packets=math.ceil(DATA_SPIKE_BYTES / 1460) + 3,
            bytes_sent=received,
            bytes_received=0,
            syn_count=1,
            connections_60s=1,
            label="attack",
        ),
        measurements={
            "connections": 1,
            "bytes_transferred": received,
            "payload": "generated_in_memory_repeated_byte",
            "owned_destination_ports": [destination_port],
            "packet_count_source": "estimated_from_bytes_not_packet_capture",
        },
    )


def run_suspicious_port_socket_scenario() -> LabObservation:
    marker = b"LOCAL-LAB\n"
    started = time.perf_counter()
    with closing(_first_available_listener(SUSPICIOUS_PORTS)) as listener:
        destination_port = int(listener.getsockname()[1])
        client, server = _connect_owned(listener)
        with closing(client), closing(server):
            source_port = int(client.getsockname()[1])
            client.sendall(marker)
            received = server.recv(4096)
    return LabObservation(
        scenario="suspicious-port",
        description="连接程序自己占用的一个可疑端口并发送无害固定标记",
        expected_rule="SUSPICIOUS_PORT",
        flow=_flow(
            src_port=source_port,
            dst_port=destination_port,
            duration_ms=_elapsed_ms(started),
            packets=5,
            bytes_sent=len(received),
            bytes_received=0,
            syn_count=1,
            label="attack",
        ),
        measurements={
            "connections": 1,
            "marker_bytes": len(received),
            "owned_destination_ports": [destination_port],
        },
    )


DEFAULT_RUNNERS: Mapping[str, Callable[[], LabObservation]] = {
    "normal": run_normal_socket_scenario,
    "port-scan": run_port_scan_socket_scenario,
    "brute-force": run_brute_force_socket_scenario,
    "connection-flood": run_connection_flood_socket_scenario,
    "data-spike": run_data_spike_socket_scenario,
    "suspicious-port": run_suspicious_port_socket_scenario,
}


def _validate_observation(observation: LabObservation) -> None:
    if observation.scenario not in SCENARIOS:
        raise ValueError("本机实验返回了未知场景")
    for address in (observation.flow.src_ip, observation.flow.dst_ip):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("本机实验返回了无效地址") from exc
        if not parsed.is_loopback:
            raise ValueError("本机实验结果包含非 loopback 地址，已拒绝")
    owned = observation.measurements.get("owned_destination_ports")
    if not isinstance(owned, list) or not owned or observation.flow.dst_port not in owned:
        raise ValueError("本机实验必须只连接程序自己占用的端口")


def run_loopback_lab(
    detector: HybridDetector,
    *,
    scenario: str = "all",
    confirmation: str = "",
    runners: Mapping[str, Callable[[], LabObservation]] | None = None,
) -> dict[str, object]:
    if confirmation != LAB_CONFIRMATION:
        raise ValueError(f"本机实验必须显式提供 confirmation='{LAB_CONFIRMATION}'")
    if scenario != "all" and scenario not in SCENARIOS:
        raise ValueError("未知本机实验场景")
    selected = list(SCENARIOS) if scenario == "all" else [scenario]
    available = DEFAULT_RUNNERS if runners is None else runners
    entries: list[dict[str, object]] = []
    for name in selected:
        runner = available.get(name)
        if runner is None:
            raise ValueError(f"本机实验缺少场景执行器: {name}")
        try:
            observation = runner()
            _validate_observation(observation)
            result = detector.analyze(observation.flow)
            passed = (
                not result.is_alert
                if observation.expected_rule is None
                else result.is_alert and observation.expected_rule in result.rule_ids
            )
            entries.append({
                "scenario": observation.scenario,
                "description": observation.description,
                "status": "passed" if passed else "failed",
                "expected_alert": observation.expected_rule is not None,
                "expected_rule": observation.expected_rule,
                "measurements": observation.measurements,
                "flow": asdict(observation.flow),
                "detection": result.to_dict(),
            })
        except OSError as exc:
            entries.append({
                "scenario": name,
                "status": "error",
                "expected_alert": name != "normal",
                "error": str(exc),
            })
    passed = bool(entries) and all(entry["status"] == "passed" for entry in entries)
    return {
        "schema_version": "1.0",
        "generated_at": _timestamp(),
        "mode": "loopback_socket_lab",
        "passed": passed,
        "model": {
            "algorithm": detector.model.algorithm,
            "version": detector.model.model_version,
            "threshold": detector.threshold,
        },
        "safety": {
            "network_target": LOOPBACK,
            "custom_or_external_targets_supported": False,
            "packet_capture": False,
            "firewall_changes": False,
            "administrator_privileges_required": False,
            "real_credentials_used": False,
            "all_destination_ports_owned_before_connect": True,
        },
        "limitations": [
            "这是实际 loopback Socket 行为，不验证 Windows pktmon 或物理网卡抓包链路。",
            "包数量由 Socket 操作或字节数估算，不是包级采集结果。",
            "认证失败来自程序自己的虚拟服务，不接触系统账户。",
            "本机实验用于功能与召回检查，不能替代跨日真实正常流量误报基线。",
        ],
        "scenarios": entries,
    }


def write_lab_report(
    report: dict[str, object], path: str | Path, *, overwrite: bool = False,
) -> None:
    validate_lab_report_output(path, overwrite=overwrite)
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def validate_lab_report_output(path: str | Path, *, overwrite: bool = False) -> None:
    output = Path(path)
    if output.suffix.casefold() != ".json":
        raise ValueError("本机实验报告必须使用 .json 扩展名")
    if output.is_symlink():
        raise ValueError("本机实验报告输出不能是符号链接")
    if output.exists() and not overwrite:
        raise ValueError(f"输出文件已存在: {output}；如需替换请添加 --overwrite")
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("本机实验临时报告已存在，请先人工检查")
