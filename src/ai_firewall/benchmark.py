from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .detector import HybridDetector
from .model import LinearModel
from .schema import FlowRecord
from .training import label_to_int


def _timestamp(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"时间戳不是有效的 ISO 8601 格式: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class TimeSplit:
    calibration: list[FlowRecord]
    test: list[FlowRecord]
    split_timestamp: str


def chronological_split(flows: list[FlowRecord], calibration_fraction: float) -> TimeSplit:
    if not 0.1 <= calibration_fraction <= 0.9:
        raise ValueError("calibration_fraction 必须在 0.1 和 0.9 之间")
    if len(flows) < 8:
        raise ValueError("误报基线至少需要 8 条带标签、带时间戳的记录")
    ordered = sorted(flows, key=lambda flow: _timestamp(flow.timestamp))
    split_index = max(1, min(len(ordered) - 1, math.floor(len(ordered) * calibration_fraction)))
    calibration = ordered[:split_index]
    test = ordered[split_index:]
    if not any(label_to_int(flow.label) == 0 for flow in calibration):
        raise ValueError("校准时间段必须包含正常样本")
    test_labels = {label_to_int(flow.label) for flow in test}
    if test_labels != {0, 1}:
        raise ValueError("独立测试时间段必须同时包含正常和攻击样本")
    return TimeSplit(calibration, test, test[0].timestamp)


def _risk_scores(model: LinearModel, flows: list[FlowRecord]) -> list[float]:
    detector = HybridDetector(model, threshold=0.5)
    return [detector.analyze(flow).risk_score for flow in flows]


def calibrate_threshold(
    model: LinearModel, calibration: list[FlowRecord], target_fpr: float,
) -> dict[str, object]:
    if not 0.0 <= target_fpr <= 0.5:
        raise ValueError("target_fpr 必须在 0 和 0.5 之间")
    scored = [
        score for score, flow in zip(_risk_scores(model, calibration), calibration)
        if label_to_int(flow.label) == 0
    ]
    if not scored:
        raise ValueError("校准时间段没有正常样本")

    candidates = {0.000001, 0.999999}
    for score in scored:
        candidates.add(min(max(math.nextafter(score, 1.0), 0.000001), 0.999999))
    selected = 0.999999
    achieved = sum(score >= selected for score in scored) / len(scored)
    for candidate in sorted(candidates):
        empirical = sum(score >= candidate for score in scored) / len(scored)
        if empirical <= target_fpr:
            selected = candidate
            achieved = empirical
            break
    return {
        "threshold": round(selected, 6),
        "target_false_positive_rate": target_fpr,
        "calibration_false_positive_rate": round(achieved, 6),
        "calibration_benign_rows": len(scored),
        "target_met": achieved <= target_fpr,
    }


def _metrics(model: LinearModel, flows: list[FlowRecord], threshold: float) -> dict[str, object]:
    detector = HybridDetector(model, threshold=threshold)
    tp = fp = tn = fn = 0
    per_day: dict[str, dict[str, int]] = {}
    for flow in flows:
        actual = label_to_int(flow.label)
        predicted = int(detector.analyze(flow).is_alert)
        tp += predicted == 1 and actual == 1
        fp += predicted == 1 and actual == 0
        tn += predicted == 0 and actual == 0
        fn += predicted == 0 and actual == 1
        day = _timestamp(flow.timestamp).date().isoformat()
        bucket = per_day.setdefault(day, {"rows": 0, "benign_rows": 0, "attack_rows": 0, "false_positives": 0})
        bucket["rows"] += 1
        bucket["benign_rows"] += actual == 0
        bucket["attack_rows"] += actual == 1
        bucket["false_positives"] += predicted == 1 and actual == 0

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    for bucket in per_day.values():
        benign = bucket["benign_rows"]
        bucket["false_positive_rate"] = round(bucket["false_positives"] / benign, 6) if benign else 0.0
    return {
        "rows": len(flows),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "false_positive_rate": round(fpr, 6),
        "false_positives_per_day": round(fp / max(len(per_day), 1), 6),
        "per_day": per_day,
    }


def build_benchmark_report(
    model: LinearModel,
    flows: list[FlowRecord],
    calibration_fraction: float = 0.4,
    target_fpr: float = 0.01,
    source: str | None = None,
) -> dict[str, object]:
    split = chronological_split(flows, calibration_fraction)
    calibration = calibrate_threshold(model, split.calibration, target_fpr)
    threshold = float(calibration["threshold"])
    test_metrics = _metrics(model, split.test, threshold)
    warnings = []
    if len(split.test) < 1000:
        warnings.append("独立测试集少于 1000 条；指标置信度有限，不能作为生产发布依据。")
    benign_test_rows = int(test_metrics["true_negative"]) + int(test_metrics["false_positive"])
    if benign_test_rows < 1000:
        warnings.append("独立测试集正常样本少于 1000 条；每日误报与 FPR 可能不稳定。")
    if not calibration["target_met"]:
        warnings.append("当前阈值无法在校准集达到目标误报率。")
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "method": "chronological_holdout_with_benign_threshold_calibration",
        "split": {
            "calibration_fraction": calibration_fraction,
            "calibration_rows": len(split.calibration),
            "test_rows": len(split.test),
            "test_starts_at": split.split_timestamp,
        },
        "calibration": calibration,
        "independent_test": test_metrics,
        "warnings": warnings,
    }


def write_benchmark_report(report: dict[str, object], path: str | Path) -> None:
    Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

