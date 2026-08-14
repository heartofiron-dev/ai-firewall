from __future__ import annotations

import json
import os
import subprocess
import csv
import io
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone

from .schema import FlowRecord


SERVER_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379}
FAILED_STATES = {"closed", "deletetcb"}


@dataclass(frozen=True)
class WindowsConnection:
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    owning_process: int
    process_name: str

    @property
    def key(self) -> tuple[object, ...]:
        return (
            self.local_address, self.local_port, self.remote_address,
            self.remote_port, self.owning_process,
        )


@dataclass(frozen=True)
class LiveObservation:
    flow: FlowRecord
    process_id: int
    process_name: str
    state: str
    direction: str


def parse_connections_json(payload: str) -> list[WindowsConnection]:
    if not payload.strip():
        return []
    data = json.loads(payload.lstrip("\ufeff"))
    rows = data if isinstance(data, list) else [data]
    connections = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        remote_port = int(row.get("remote_port") or 0)
        if remote_port <= 0:
            continue
        connections.append(WindowsConnection(
            local_address=str(row.get("local_address") or ""),
            local_port=int(row.get("local_port") or 0),
            remote_address=str(row.get("remote_address") or ""),
            remote_port=remote_port,
            state=str(row.get("state") or "Unknown"),
            owning_process=int(row.get("owning_process") or 0),
            process_name=str(row.get("process_name") or "unknown"),
        ))
    return connections


def _collect_with_powershell(timeout: float) -> list[WindowsConnection]:
    script = r'''
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$items = Get-NetTCPConnection -ErrorAction Stop |
  Where-Object { $_.RemotePort -gt 0 -and $_.State -ne 'Listen' } |
  ForEach-Object {
    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
      local_address = $_.LocalAddress
      local_port = $_.LocalPort
      remote_address = $_.RemoteAddress
      remote_port = $_.RemotePort
      state = $_.State.ToString()
      owning_process = $_.OwningProcess
      process_name = if ($process) { $process.ProcessName } else { 'unknown' }
    }
  }
ConvertTo-Json -InputObject @($items) -Compress
'''
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or "Get-NetTCPConnection 执行失败"
        raise OSError(message)
    return parse_connections_json(completed.stdout)


def _split_endpoint(value: str) -> tuple[str, int]:
    address, separator, port = value.rpartition(":")
    if not separator:
        raise ValueError(f"无法解析网络端点: {value}")
    return address.strip("[]"), int(port)


def parse_netstat_output(payload: str, process_names: dict[int, str] | None = None) -> list[WindowsConnection]:
    names = process_names or {}
    state_names = {
        "ESTABLISHED": "Established", "SYN_SENT": "SynSent",
        "SYN_RECEIVED": "SynReceived", "TIME_WAIT": "TimeWait",
        "CLOSE_WAIT": "CloseWait", "FIN_WAIT_1": "FinWait1",
        "FIN_WAIT_2": "FinWait2", "LAST_ACK": "LastAck",
        "CLOSED": "Closed", "DELETE_TCB": "DeleteTcb",
    }
    connections = []
    for line in payload.splitlines():
        fields = line.split()
        if len(fields) != 5 or fields[0].upper() != "TCP":
            continue
        try:
            local_address, local_port = _split_endpoint(fields[1])
            remote_address, remote_port = _split_endpoint(fields[2])
            process_id = int(fields[4])
        except ValueError:
            continue
        if remote_port <= 0 or fields[3].upper() == "LISTENING":
            continue
        connections.append(WindowsConnection(
            local_address=local_address,
            local_port=local_port,
            remote_address=remote_address,
            remote_port=remote_port,
            state=state_names.get(fields[3].upper(), fields[3]),
            owning_process=process_id,
            process_name=names.get(process_id, "unknown"),
        ))
    return connections


def _tasklist_names(timeout: float) -> dict[int, str]:
    completed = subprocess.run(
        ["tasklist.exe", "/FO", "CSV", "/NH"], capture_output=True,
        text=True, errors="replace", timeout=timeout, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        return {}
    names = {}
    for row in csv.reader(io.StringIO(completed.stdout)):
        if len(row) < 2:
            continue
        try:
            names[int(row[1])] = row[0]
        except ValueError:
            continue
    return names


def _collect_with_netstat(timeout: float) -> list[WindowsConnection]:
    completed = subprocess.run(
        ["netstat.exe", "-ano", "-p", "tcp"], capture_output=True,
        text=True, errors="replace", timeout=timeout, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise OSError(completed.stderr.strip() or "netstat 执行失败")
    return parse_netstat_output(completed.stdout, _tasklist_names(timeout))


def collect_connections(timeout: float = 12.0) -> list[WindowsConnection]:
    if os.name != "nt":
        raise OSError("实时连接监控当前只支持 Windows")
    try:
        return _collect_with_powershell(timeout)
    except (OSError, subprocess.SubprocessError):
        # Get-NetTCPConnection can be denied in restricted desktop sessions.
        # netstat remains read-only and does not require an elevated shell.
        return _collect_with_netstat(timeout)


class WindowsFlowTracker:
    """Converts newly observed Windows TCP connections into 60-second flow context."""

    def __init__(self) -> None:
        self._previous_keys: set[tuple[object, ...]] = set()
        self._recent: dict[tuple[str, int, str], deque[tuple[float, str, int, bool]]] = defaultdict(deque)

    def observe(self, connections: list[WindowsConnection], now: float) -> list[LiveObservation]:
        current_keys = {connection.key for connection in connections}
        new_connections = [connection for connection in connections if connection.key not in self._previous_keys]
        self._previous_keys = current_keys
        observations = []
        timestamp = datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")

        for connection in new_connections:
            inbound = connection.local_port in SERVER_PORTS and connection.remote_port > 1024
            if inbound:
                src_ip, dst_ip = connection.remote_address, connection.local_address
                src_port, dst_port = connection.remote_port, connection.local_port
                direction = "inbound"
            else:
                src_ip, dst_ip = connection.local_address, connection.remote_address
                src_port, dst_port = connection.local_port, connection.remote_port
                direction = "outbound"

            failed = connection.state.lower() in FAILED_STATES
            # Process-scoped windows prevent unrelated desktop applications and
            # loopback services from combining into a false port-scan alert.
            recent = self._recent[(src_ip, connection.owning_process, direction)]
            while recent and recent[0][0] < now - 60:
                recent.popleft()
            recent.append((now, dst_ip, dst_port, failed))
            state_lower = connection.state.lower()
            flow = FlowRecord(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol="TCP",
                duration_ms=0.0,
                packets=1,
                bytes_sent=0,
                bytes_received=0,
                syn_count=int(state_lower in {"synsent", "synreceived"}),
                rst_count=0,
                unique_dst_ports_60s=len({item[2] for item in recent}),
                connections_60s=len(recent),
                failed_connections_60s=sum(item[3] for item in recent),
            )
            observations.append(LiveObservation(
                flow=flow,
                process_id=connection.owning_process,
                process_name=connection.process_name,
                state=connection.state,
                direction=direction,
            ))
        return observations
