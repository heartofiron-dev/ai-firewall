from __future__ import annotations

import json
import os
import platform
import statistics
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

from .detector import HybridDetector
from .schema import FlowRecord


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def build_performance_report(
    detector: HybridDetector,
    flows: list[FlowRecord],
    *,
    iterations: int = 100,
    warmup: int = 10,
    max_p95_ms: float = 5.0,
    max_peak_mib: float = 128.0,
) -> dict[str, object]:
    if not flows:
        raise ValueError("性能测试至少需要 1 条网络流")
    if not 1 <= iterations <= 10000 or not 0 <= warmup <= 1000:
        raise ValueError("iterations 必须为 1..10000，warmup 必须为 0..1000")
    if max_p95_ms <= 0 or max_peak_mib <= 0:
        raise ValueError("性能门槛必须大于 0")
    for index in range(warmup):
        detector.analyze(flows[index % len(flows)])

    latencies = []
    alerts = 0
    tracemalloc.start()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    try:
        for _ in range(iterations):
            for flow in flows:
                started = time.perf_counter_ns()
                alerts += detector.analyze(flow).is_alert
                latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        cpu_seconds = time.process_time() - cpu_start
        wall_seconds = time.perf_counter() - wall_start
        current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    processed = len(latencies)
    p95 = _percentile(latencies, 0.95)
    peak_mib = peak_bytes / (1024 * 1024)
    metrics = {
        "flows_processed": processed,
        "alerts": alerts,
        "wall_seconds": round(wall_seconds, 6),
        "cpu_seconds": round(cpu_seconds, 6),
        "cpu_percent_single_core": round(100.0 * cpu_seconds / max(wall_seconds, 1e-9), 2),
        "throughput_flows_per_second": round(processed / max(wall_seconds, 1e-9), 2),
        "latency_ms": {
            "mean": round(statistics.fmean(latencies), 6),
            "p50": round(_percentile(latencies, 0.50), 6),
            "p95": round(p95, 6),
            "p99": round(_percentile(latencies, 0.99), 6),
            "max": round(max(latencies), 6),
        },
        "traced_memory_mib": {
            "current": round(current_bytes / (1024 * 1024), 6),
            "peak": round(peak_mib, 6),
        },
    }
    checks = {
        "p95_latency": {"limit_ms": max_p95_ms, "passed": p95 <= max_p95_ms},
        "peak_memory": {"limit_mib": max_peak_mib, "passed": peak_mib <= max_peak_mib},
    }
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "single_process_warmup_then_repeated_flow_analysis",
        "runtime": {
            "python": platform.python_version(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "logical_cpu_count": os.cpu_count(),
        },
        "configuration": {
            "source_rows": len(flows), "iterations": iterations, "warmup": warmup,
            "model_version": detector.model.model_version,
            "threshold": detector.threshold,
        },
        "metrics": metrics,
        "checks": checks,
        "passed": all(item["passed"] for item in checks.values()),
        "notes": [
            "tracemalloc 只统计 Python 分配，不包含解释器与操作系统全部常驻内存。",
            "CPU 百分比按单核进程时间/墙钟时间估算；目标设备应重复运行并保留原始报告。",
        ],
    }


def write_performance_report(report: dict[str, object], path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
