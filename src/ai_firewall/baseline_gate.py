from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_REPORT_BYTES = 20 * 1024 * 1024


def _load_object(path: str | Path, label: str) -> dict[str, Any]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"{label} 必须是普通 JSON 文件")
    if source.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"{label} 超过 20 MiB 安全上限")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} 不是有效 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} 必须是 JSON 对象")
    return payload


def evaluate_baseline_gate(
    benchmark_report: str | Path,
    provenance_file: str | Path,
    *,
    min_days: int = 3,
    min_benign_rows: int = 1000,
    max_fpr: float = 0.01,
    max_false_positives_per_day: float = 10.0,
    min_recall: float = 0.80,
) -> dict[str, object]:
    if min_days < 2 or min_benign_rows < 100:
        raise ValueError("发布门槛至少需要 2 天和 100 条正常独立测试记录")
    if not 0 <= max_fpr <= 0.5 or not 0 <= min_recall <= 1:
        raise ValueError("FPR/Recall 门槛无效")
    report = _load_object(benchmark_report, "基线报告")
    provenance = _load_object(provenance_file, "数据来源声明")
    if report.get("schema_version") != "1.0":
        raise ValueError("不支持的基线报告版本")
    required_text = ("environment_id", "authorization_scope", "collection_period", "labeling_method")
    text_checks = {
        name: isinstance(provenance.get(name), str) and bool(provenance[name].strip())
        for name in required_text
    }
    attestation_checks = {
        "authorization_confirmed": provenance.get("authorization_confirmed") is True,
        "anonymization_confirmed": provenance.get("anonymization_confirmed") is True,
        "private_payloads_excluded": provenance.get("private_payloads_excluded") is True,
        "independent_holdout_confirmed": provenance.get("independent_holdout_confirmed") is True,
    }
    metrics = report.get("independent_test")
    calibration = report.get("calibration")
    if not isinstance(metrics, dict) or not isinstance(calibration, dict):
        raise ValueError("基线报告缺少校准或独立测试指标")
    per_day = metrics.get("per_day")
    if not isinstance(per_day, dict):
        raise ValueError("基线报告缺少逐日指标")
    benign = int(metrics.get("true_negative", 0)) + int(metrics.get("false_positive", 0))
    metric_checks = {
        "calibration_target_met": calibration.get("target_met") is True,
        "minimum_independent_days": len(per_day) >= min_days,
        "minimum_benign_rows": benign >= min_benign_rows,
        "maximum_false_positive_rate": float(metrics.get("false_positive_rate", 1.0)) <= max_fpr,
        "maximum_false_positives_per_day": (
            float(metrics.get("false_positives_per_day", float("inf")))
            <= max_false_positives_per_day
        ),
        "minimum_recall": float(metrics.get("recall", 0.0)) >= min_recall,
    }
    checks = text_checks | attestation_checks | metric_checks
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "observed": {
            "independent_days": len(per_day),
            "benign_rows": benign,
            "false_positive_rate": metrics.get("false_positive_rate"),
            "false_positives_per_day": metrics.get("false_positives_per_day"),
            "recall": metrics.get("recall"),
        },
        "thresholds": {
            "min_days": min_days,
            "min_benign_rows": min_benign_rows,
            "max_fpr": max_fpr,
            "max_false_positives_per_day": max_false_positives_per_day,
            "min_recall": min_recall,
        },
        "environment_id": provenance.get("environment_id"),
        "warning": (
            "通过只表示这份获授权数据达到所配置门槛，不代表可在其他设备或网络自动封禁。"
        ),
    }


def write_gate_report(report: dict[str, object], path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
