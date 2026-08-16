from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable


MAX_STATE_BYTES = 2 * 1024 * 1024
DEFAULT_ALLOWLIST = (
    "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12",
    "192.168.0.0/16", "169.254.0.0/16", "fe80::/10", "fc00::/7",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def load_allowlist(path: str | Path | None = None) -> list[ipaddress._BaseNetwork]:
    values = list(DEFAULT_ALLOWLIST)
    if path is not None:
        source = Path(path)
        if source.is_symlink():
            raise ValueError("允许名单不能是符号链接")
        if source.stat().st_size > 64 * 1024:
            raise ValueError("允许名单超过 64 KiB 安全上限")
        values.extend(
            line.split("#", 1)[0].strip()
            for line in source.read_text(encoding="utf-8-sig").splitlines()
            if line.split("#", 1)[0].strip()
        )
    try:
        return [ipaddress.ip_network(value, strict=False) for value in values]
    except ValueError as exc:
        raise ValueError(f"允许名单包含无效 CIDR: {exc}") from exc


def validate_block_target(address: str, allowlist: list[ipaddress._BaseNetwork]) -> str:
    try:
        target = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError("只能临时封禁单个有效 IP 地址") from exc
    if target.is_unspecified or target.is_multicast or target.is_loopback or target.is_link_local:
        raise ValueError("拒绝封禁本机、组播、未指定或链路本地地址")
    if any(target.version == network.version and target in network for network in allowlist):
        raise ValueError("目标位于允许名单，拒绝封禁")
    return target.compressed


def _rule_name(address: str) -> str:
    return "AI-Firewall-" + hashlib.sha256(address.encode()).hexdigest()[:16]


def _read_state(path: Path) -> dict[str, object]:
    if path.is_symlink():
        raise ValueError("防火墙状态文件不能是符号链接")
    if not path.exists():
        return {"schema_version": "1.0", "rules": []}
    if path.stat().st_size > MAX_STATE_BYTES:
        raise ValueError("防火墙状态文件超过 2 MiB 安全上限")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError("防火墙状态文件格式无效")
    return data


def _write_state(path: Path, state: dict[str, object]) -> None:
    if path.is_symlink():
        raise ValueError("防火墙状态文件不能是符号链接")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("防火墙临时状态文件已存在，请先人工检查")
    temporary.write_text(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _powershell_runner(script: str, arguments: list[str]) -> None:
    if os.name != "nt":
        raise OSError("Windows 防火墙集成只支持 Windows")
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script, *arguments],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=30, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise OSError(completed.stderr.strip() or "Windows 防火墙命令失败")


ADD_SCRIPT = (
    "& { param($RuleName,$RemoteAddress,$Direction) "
    "New-NetFirewallRule -DisplayName $RuleName -Name $RuleName "
    "-Group 'AI Firewall' -Direction $Direction -Action Block "
    "-RemoteAddress $RemoteAddress -Profile Any -Enabled True -ErrorAction Stop | Out-Null }"
)
REMOVE_SCRIPT = (
    "& { param($RuleName) Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue | "
    "Remove-NetFirewallRule -ErrorAction Stop }"
)


def _managed_names(rule: dict[str, object]) -> list[str]:
    values = rule.get("names")
    if isinstance(values, list) and values:
        names = [str(value) for value in values]
    else:
        names = [str(rule.get("name") or "")]
    return names if all(name.startswith("AI-Firewall-") for name in names) else []


def plan_temporary_block(
    address: str, duration_seconds: int, *, allowlist_path: str | Path | None = None,
) -> dict[str, object]:
    if not 60 <= duration_seconds <= 86400:
        raise ValueError("临时封禁时长必须在 60 秒到 24 小时之间")
    target = validate_block_target(address, load_allowlist(allowlist_path))
    created = _now()
    base_name = _rule_name(target)
    return {
        "name": base_name,
        "names": [base_name + "-In", base_name + "-Out"],
        "remote_address": target,
        "duration_seconds": duration_seconds,
        "created_at": created.isoformat(),
        "expires_at": (created + timedelta(seconds=duration_seconds)).isoformat(),
    }


def apply_temporary_block(
    address: str,
    duration_seconds: int,
    state_path: str | Path,
    *,
    allowlist_path: str | Path | None = None,
    confirmation: str = "",
    runner: Callable[[str, list[str]], None] = _powershell_runner,
) -> dict[str, object]:
    if confirmation != "APPLY":
        raise ValueError("实际封禁必须显式提供 confirmation='APPLY'")
    state_file = Path(state_path)
    if state_file.with_name(state_file.name + ".disabled").exists():
        raise ValueError("kill switch 已启用；拒绝新增防火墙规则")
    plan = plan_temporary_block(address, duration_seconds, allowlist_path=allowlist_path)
    state = _read_state(state_file)
    rules = list(state["rules"])
    if any(item.get("name") == plan["name"] for item in rules if isinstance(item, dict)):
        raise ValueError("该地址已有 AI Firewall 托管规则")
    created_names = []
    try:
        for name, direction in zip(plan["names"], ("Inbound", "Outbound")):
            runner(ADD_SCRIPT, [str(name), str(plan["remote_address"]), direction])
            created_names.append(str(name))
    except Exception:
        for name in created_names:
            runner(REMOVE_SCRIPT, [name])
        raise
    rules.append(plan)
    state["rules"] = rules
    try:
        _write_state(state_file, state)
    except Exception:
        for name in created_names:
            runner(REMOVE_SCRIPT, [name])
        raise
    return {"applied": True, "rule": plan}


def rollback_rules(
    state_path: str | Path,
    *,
    confirmation: str = "",
    runner: Callable[[str, list[str]], None] = _powershell_runner,
) -> dict[str, int]:
    if confirmation != "ROLLBACK":
        raise ValueError("回滚必须显式提供 confirmation='ROLLBACK'")
    state_file = Path(state_path)
    state = _read_state(state_file)
    rules = [item for item in state["rules"] if isinstance(item, dict)]
    removed = 0
    remaining = []
    for rule in rules:
        names = _managed_names(rule)
        if not names:
            remaining.append(rule)
            continue
        try:
            for name in names:
                runner(REMOVE_SCRIPT, [name])
        except OSError:
            remaining.append(rule)
        else:
            removed += 1
    state["rules"] = remaining
    _write_state(state_file, state)
    return {"removed": removed, "remaining": len(remaining)}


def cleanup_expired_rules(
    state_path: str | Path,
    *,
    confirmation: str = "",
    now: datetime | None = None,
    runner: Callable[[str, list[str]], None] = _powershell_runner,
) -> dict[str, int]:
    if confirmation != "CLEANUP":
        raise ValueError("清理到期规则必须显式提供 confirmation='CLEANUP'")
    state_file = Path(state_path)
    state = _read_state(state_file)
    current = now or _now()
    rules = [item for item in state["rules"] if isinstance(item, dict)]
    removed = 0
    remaining = []
    for rule in rules:
        try:
            expires = datetime.fromisoformat(str(rule.get("expires_at")))
        except ValueError:
            remaining.append(rule)
            continue
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        names = _managed_names(rule)
        if expires > current or not names:
            remaining.append(rule)
            continue
        try:
            for name in names:
                runner(REMOVE_SCRIPT, [name])
        except OSError:
            remaining.append(rule)
        else:
            removed += 1
    state["rules"] = remaining
    _write_state(state_file, state)
    return {"removed": removed, "remaining": len(remaining)}


def activate_kill_switch(
    state_path: str | Path,
    *,
    rollback: bool = False,
    confirmation: str = "",
    runner: Callable[[str, list[str]], None] = _powershell_runner,
) -> dict[str, object]:
    state_file = Path(state_path)
    marker = state_file.with_name(state_file.name + ".disabled")
    marker.parent.mkdir(parents=True, exist_ok=True)
    if marker.is_symlink():
        raise ValueError("kill switch 标记不能是符号链接")
    marker.write_text(_now().isoformat() + "\n", encoding="utf-8")
    result: dict[str, object] = {"disabled": True, "rolled_back": 0}
    if rollback:
        rolled = rollback_rules(state_file, confirmation=confirmation, runner=runner)
        result["rolled_back"] = rolled["removed"]
        result["remaining"] = rolled["remaining"]
    return result


def deactivate_kill_switch(state_path: str | Path, *, confirmation: str = "") -> bool:
    if confirmation != "ENABLE":
        raise ValueError("重新允许封禁必须显式提供 confirmation='ENABLE'")
    state_file = Path(state_path)
    marker = state_file.with_name(state_file.name + ".disabled")
    if marker.is_symlink():
        raise ValueError("kill switch 标记不能是符号链接")
    if not marker.exists():
        return False
    marker.unlink()
    return True
