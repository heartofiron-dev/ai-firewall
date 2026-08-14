from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def validate_capture_request(
    duration: float, output: str | Path, overwrite: bool = False,
    platform_name: str | None = None,
) -> Path:
    if (platform_name or os.name) != "nt":
        raise OSError("pktmon 包级采集当前只支持 Windows")
    if not 1 <= duration <= 3600:
        raise ValueError("采集时长必须在 1 到 3600 秒之间")
    output_path = Path(output).resolve()
    if output_path.suffix.lower() != ".pcapng":
        raise ValueError("包级采集输出文件必须使用 .pcapng 扩展名")
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"输出文件已存在: {output_path}；使用 --overwrite 才能覆盖")
    return output_path


def build_pktmon_commands(etl_path: Path, output_path: Path) -> tuple[list[str], list[str], list[str]]:
    return (
        ["pktmon.exe", "start", "--capture", "--pkt-size", "0", "--file-name", str(etl_path)],
        ["pktmon.exe", "stop"],
        ["pktmon.exe", "etl2pcap", str(etl_path), "--out", str(output_path)],
    )


def _run(command: list[str], timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command, capture_output=True, text=True, errors="replace", timeout=timeout,
        check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "pktmon 命令执行失败"
        raise OSError(message)
    return completed


def capture_with_pktmon(
    duration: float, output: str | Path, overwrite: bool = False,
) -> Path:
    """Capture packets locally for a bounded duration and convert ETL to PCAPNG."""
    output_path = validate_capture_request(duration, output, overwrite)
    if shutil.which("pktmon.exe") is None:
        raise OSError("系统未找到 pktmon.exe；需要 Windows 10 2004 或更新版本")
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        is_admin = False
    if not is_admin:
        raise PermissionError("pktmon 包级采集需要以管理员身份运行终端")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, etl_name = tempfile.mkstemp(prefix="ai-firewall-", suffix=".etl", dir=output_path.parent)
    os.close(descriptor)
    etl_path = Path(etl_name)
    etl_path.unlink(missing_ok=True)
    start_command, stop_command, convert_command = build_pktmon_commands(etl_path, output_path)
    started = False
    try:
        _run(start_command)
        started = True
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            pass
        finally:
            if started:
                _run(stop_command)
                started = False
        if output_path.exists() and overwrite:
            output_path.unlink()
        _run(convert_command, timeout=120.0)
        if not output_path.exists():
            raise OSError("pktmon 转换结束但未生成 PCAPNG 文件")
        return output_path
    finally:
        if started:
            try:
                _run(stop_command)
            except OSError:
                pass
        etl_path.unlink(missing_ok=True)

