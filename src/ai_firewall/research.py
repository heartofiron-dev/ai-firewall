from __future__ import annotations

import csv
import json
import math
import time
from datetime import datetime, timezone
from html import escape
from itertools import product
from pathlib import Path
from typing import Callable, Sequence

from .comparison import (
    _calibrate_threshold,
    _linear_model,
    _matrix,
    _timestamp,
    chronological_model_split,
)
from .features import FEATURE_NAMES
from .rules import evaluate_rules
from .schema import FlowRecord
from .training import label_to_int, train_logistic_model


DEFAULT_TARGET_FPRS = (0.005, 0.01, 0.02)
DEFAULT_RESEARCH_SEEDS = (11, 23, 42, 67, 89)
DEFAULT_LIGHTGBM_GRID = {
    "n_estimators": (100, 200, 400),
    "learning_rate": (0.03, 0.05, 0.10),
    "num_leaves": (15, 31),
    "min_child_samples": (20, 50),
}


def _average_precision(scores: Sequence[float], labels: Sequence[int]) -> float:
    positives = sum(labels)
    if positives == 0:
        return 0.0
    ranked = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    true_positives = false_positives = 0
    previous_recall = 0.0
    average_precision = 0.0
    index = 0
    while index < len(ranked):
        score = ranked[index][0]
        group_positives = group_negatives = 0
        while index < len(ranked) and ranked[index][0] == score:
            if ranked[index][1]:
                group_positives += 1
            else:
                group_negatives += 1
            index += 1
        true_positives += group_positives
        false_positives += group_negatives
        recall = true_positives / positives
        precision = true_positives / (true_positives + false_positives)
        average_precision += (recall - previous_recall) * precision
        previous_recall = recall
    return average_precision


def _wilson_interval(successes: int, total: int) -> dict[str, float]:
    if total == 0:
        return {"lower": 0.0, "upper": 0.0}
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1.0 + z * z / total
    centre = (proportion + z * z / (2.0 * total)) / denominator
    radius = z * math.sqrt(
        proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)
    ) / denominator
    return {
        "lower": round(max(0.0, centre - radius), 6),
        "upper": round(min(1.0, centre + radius), 6),
    }


def _percentile(values: Sequence[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _metrics(
    scores: Sequence[float], labels: Sequence[int], threshold: float,
    explainable: Sequence[bool],
) -> dict[str, object]:
    if not (len(scores) == len(labels) == len(explainable)):
        raise ValueError("模型分数、测试标签与解释标记数量不一致")
    tp = fp = tn = fn = explained_alerts = 0
    for score, actual, has_explanation in zip(scores, labels, explainable):
        predicted = int(score >= threshold)
        tp += predicted == 1 and actual == 1
        fp += predicted == 1 and actual == 0
        tn += predicted == 0 and actual == 0
        fn += predicted == 0 and actual == 1
        explained_alerts += predicted == 1 and has_explanation
    alerts = tp + fp
    precision = tp / alerts if alerts else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return {
        "rows": len(labels),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(2.0 * precision * recall / (precision + recall), 6)
        if precision + recall else 0.0,
        "false_positive_rate": round(false_positive_rate, 6),
        "recall_ci95": _wilson_interval(tp, tp + fn),
        "false_positive_rate_ci95": _wilson_interval(fp, fp + tn),
        "alerts": alerts,
        "explanation_coverage": round(explained_alerts / alerts, 6) if alerts else None,
    }


def _timed_scores(
    scorer: Callable[[list[list[float]], list[FlowRecord]], list[float]],
    matrix: list[list[float]], flows: list[FlowRecord], batch_size: int,
) -> tuple[list[float], float, list[float]]:
    scores: list[float] = []
    microseconds_per_row: list[float] = []
    started = time.perf_counter()
    for offset in range(0, len(flows), batch_size):
        matrix_batch = matrix[offset:offset + batch_size]
        flow_batch = flows[offset:offset + batch_size]
        batch_started = time.perf_counter()
        batch_scores = scorer(matrix_batch, flow_batch)
        elapsed = time.perf_counter() - batch_started
        if len(batch_scores) != len(flow_batch):
            raise ValueError("模型返回的分数数量与输入批次不一致")
        scores.extend(float(score) for score in batch_scores)
        microseconds_per_row.append(elapsed * 1_000_000.0 / max(1, len(flow_batch)))
    total_seconds = time.perf_counter() - started
    if not all(math.isfinite(score) for score in scores):
        raise ValueError("模型产生了 NaN 或 Infinity 分数")
    return scores, total_seconds, microseconds_per_row


def _sample_indices(total: int, limit: int) -> list[int]:
    """Return deterministic, time-spanning indices without replacement."""
    if total <= 0 or limit <= 0:
        return []
    count = min(total, limit)
    if count == total:
        return list(range(total))
    if count == 1:
        return [total // 2]
    return sorted({
        round(index * (total - 1) / (count - 1))
        for index in range(count)
    })


def _normalise_shap_output(explanation: object) -> tuple[object, object]:
    """Normalize binary-class SHAP outputs to rows x features and row bases."""
    import numpy as np

    values = np.asarray(getattr(explanation, "values"), dtype=float)
    base_values = np.asarray(getattr(explanation, "base_values"), dtype=float)
    if values.ndim == 3:
        if values.shape[2] != 2:
            raise ValueError(f"不支持的多输出 SHAP 形状: {values.shape}")
        values = values[:, :, 1]
        if base_values.ndim >= 2:
            base_values = base_values[:, 1]
        elif base_values.ndim == 1 and base_values.size == 2:
            base_values = np.repeat(base_values[1], values.shape[0])
    if values.ndim != 2 or values.shape[1] != len(FEATURE_NAMES):
        raise ValueError(f"SHAP 特征形状与项目特征不一致: {values.shape}")
    if base_values.ndim == 0:
        base_values = np.repeat(float(base_values), values.shape[0])
    else:
        base_values = base_values.reshape(-1)
        if base_values.size == 1:
            base_values = np.repeat(float(base_values[0]), values.shape[0])
    if base_values.size != values.shape[0]:
        raise ValueError("SHAP 基准值数量与解释行数不一致")
    if not np.isfinite(values).all() or not np.isfinite(base_values).all():
        raise ValueError("SHAP 产生了 NaN 或 Infinity")
    return values, base_values


def _configure_matplotlib_cache() -> None:
    import os
    import tempfile

    cache = Path(tempfile.gettempdir()) / "ai-firewall-matplotlib-cache"
    cache.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(cache))


def _build_lightgbm_shap_analysis(
    *, model: object, calibration_matrix: list[list[float]],
    calibration_labels: list[int], test_matrix: list[list[float]],
    test_flows: list[FlowRecord], test_labels: list[int],
    test_scores: list[float], lightgbm_configuration: dict[str, object],
    background_size: int, summary_size: int,
) -> dict[str, object]:
    _configure_matplotlib_cache()
    try:
        import numpy as np
        import shap
    except ImportError as exc:
        raise ValueError(
            "SHAP 解释需要 explainability 依赖；请运行 "
            'python -m pip install -e ".[explainability]"'
        ) from exc
    if not 10 <= background_size <= 100:
        raise ValueError("SHAP background_size 必须在 10 到 100 之间")
    if summary_size < 10:
        raise ValueError("SHAP summary_size 必须至少为 10")
    benign_calibration = [
        row for row, label in zip(calibration_matrix, calibration_labels) if label == 0
    ]
    if not benign_calibration:
        raise ValueError("校准段没有正常流量，无法构建 SHAP 背景分布")
    background_indices = _sample_indices(len(benign_calibration), background_size)
    background = np.asarray(
        [benign_calibration[index] for index in background_indices], dtype=float,
    )
    explainer = shap.TreeExplainer(
        model,
        data=background,
        feature_perturbation="interventional",
        model_output="probability",
        feature_names=FEATURE_NAMES,
    )

    thresholds = [
        float(point["calibration"]["threshold"])
        for point in lightgbm_configuration["operating_points"].values()
    ]
    alert_indices = [
        index for index, score in enumerate(test_scores)
        if any(score >= threshold for threshold in thresholds)
    ]
    alert_values = np.empty((0, len(FEATURE_NAMES)), dtype=float)
    alert_bases = np.empty((0,), dtype=float)
    if alert_indices:
        alert_explanation = explainer(
            np.asarray([test_matrix[index] for index in alert_indices], dtype=float),
            check_additivity=False,
        )
        alert_values, alert_bases = _normalise_shap_output(alert_explanation)

    alert_rows: list[dict[str, object]] = []
    local_examples: list[dict[str, object]] = []
    true_positive_examples = false_positive_examples = 0
    for position, test_index in enumerate(alert_indices):
        contributions = alert_values[position]
        ranked = sorted(
            range(len(FEATURE_NAMES)),
            key=lambda feature_index: abs(float(contributions[feature_index])),
            reverse=True,
        )
        top = [
            {
                "feature": FEATURE_NAMES[feature_index],
                "feature_value": round(float(test_matrix[test_index][feature_index]), 6),
                "shap_value": round(float(contributions[feature_index]), 8),
            }
            for feature_index in ranked[:3]
        ]
        alert_rows.append({
            "test_row_index": test_index,
            "timestamp": test_flows[test_index].timestamp,
            "actual_label": int(test_labels[test_index]),
            "score": round(float(test_scores[test_index]), 8),
            "base_value": round(float(alert_bases[position]), 8),
            "top_contributions": top,
        })
        is_true_positive = test_labels[test_index] == 1
        if (
            (is_true_positive and true_positive_examples < 3)
            or (not is_true_positive and false_positive_examples < 3)
        ):
            local_examples.append({
                "test_row_index": test_index,
                "timestamp": test_flows[test_index].timestamp,
                "actual_label": int(test_labels[test_index]),
                "score": round(float(test_scores[test_index]), 8),
                "base_value": float(alert_bases[position]),
                "feature_values": [float(value) for value in test_matrix[test_index]],
                "shap_values": [float(value) for value in contributions],
            })
            if is_true_positive:
                true_positive_examples += 1
            else:
                false_positive_examples += 1

    summary_indices = _sample_indices(len(test_matrix), summary_size)
    summary_matrix = np.asarray([test_matrix[index] for index in summary_indices], dtype=float)
    summary_explanation = explainer(summary_matrix, check_additivity=False)
    summary_values, summary_bases = _normalise_shap_output(summary_explanation)
    mean_abs = np.mean(np.abs(summary_values), axis=0)
    global_importance = sorted(
        [
            {"feature": feature, "mean_absolute_shap": round(float(value), 8)}
            for feature, value in zip(FEATURE_NAMES, mean_abs)
        ],
        key=lambda item: float(item["mean_absolute_shap"]),
        reverse=True,
    )
    return {
        "library": "shap",
        "library_version": getattr(shap, "__version__", "unknown"),
        "explainer": "TreeExplainer",
        "feature_perturbation": "interventional",
        "model_output": "probability",
        "background_scope": "time_spanning_benign_calibration_rows",
        "background_rows": len(background_indices),
        "explained_alert_rows": len(alert_indices),
        "alert_scope": "union_of_alerts_across_all_reported_target_fprs",
        "global_summary_scope": "deterministic_time_spanning_independent_test_sample",
        "global_summary_rows": len(summary_indices),
        "feature_names": list(FEATURE_NAMES),
        "global_importance": global_importance,
        "summary": {
            "test_row_indices": summary_indices,
            "feature_values": summary_matrix.tolist(),
            "shap_values": summary_values.tolist(),
            "base_values": summary_bases.tolist(),
        },
        "alerts": alert_rows,
        "local_examples": local_examples,
        "interpretation_warning": (
            "SHAP attributes this fitted model's predictions; it does not establish causal effects."
        ),
    }


def _evaluate_configuration(
    *, name: str, metadata: dict[str, object], fit_seconds: float,
    scorer: Callable[[list[list[float]], list[FlowRecord]], list[float]],
    calibration_matrix: list[list[float]], calibration_flows: list[FlowRecord],
    calibration_labels: list[int], test_matrix: list[list[float]],
    test_flows: list[FlowRecord], test_labels: list[int],
    explanation_flags: Callable[[list[FlowRecord]], list[bool]],
    target_fprs: Sequence[float], batch_size: int,
) -> dict[str, object]:
    calibration_scores, calibration_seconds, calibration_batches = _timed_scores(
        scorer, calibration_matrix, calibration_flows, batch_size,
    )
    test_scores, test_seconds, test_batches = _timed_scores(
        scorer, test_matrix, test_flows, batch_size,
    )
    benign_scores = [
        score for score, label in zip(calibration_scores, calibration_labels) if label == 0
    ]
    explainable = explanation_flags(test_flows)
    average_precision = round(_average_precision(test_scores, test_labels), 6)
    operating_points: dict[str, object] = {}
    for target_fpr in target_fprs:
        calibration = _calibrate_threshold(benign_scores, target_fpr)
        metrics = _metrics(
            test_scores, test_labels, float(calibration["threshold"]), explainable,
        )
        metrics["average_precision"] = average_precision
        operating_points[f"{target_fpr:g}"] = {
            "calibration": {
                **calibration,
                "threshold": float(calibration["threshold"]),
                "calibration_false_positive_rate": round(
                    float(calibration["calibration_false_positive_rate"]), 6,
                ),
            },
            "independent_test": metrics,
        }
    batch_latencies = calibration_batches + test_batches
    score_seconds = calibration_seconds + test_seconds
    total_scored_rows = len(calibration_flows) + len(test_flows)
    return {
        "name": name,
        "metadata": metadata,
        "fit_seconds": round(fit_seconds, 6),
        "score_seconds": round(score_seconds, 6),
        "latency": {
            "measurement": "batched_wall_clock_microseconds_per_row",
            "batch_size": batch_size,
            "scored_rows": total_scored_rows,
            "mean_us_per_row": round(score_seconds * 1_000_000.0 / total_scored_rows, 6),
            "p50_us_per_row": round(_percentile(batch_latencies, 0.50), 6),
            "p95_us_per_row": round(_percentile(batch_latencies, 0.95), 6),
            "p99_us_per_row": round(_percentile(batch_latencies, 0.99), 6),
            "throughput_rows_per_second": round(total_scored_rows / score_seconds, 3)
            if score_seconds else 0.0,
        },
        "operating_points": operating_points,
    }


def _strict_inner_boundary(
    flows: Sequence[FlowRecord], boundary: int, minimum: int,
) -> int:
    """Move a boundary left so equal timestamps cannot occur on both sides."""
    timestamps = [_timestamp(flow.timestamp) for flow in flows]
    while boundary > minimum and timestamps[boundary - 1] == timestamps[boundary]:
        boundary -= 1
    if boundary <= minimum or timestamps[boundary - 1] >= timestamps[boundary]:
        raise ValueError("内部时间戳分组过大，无法建立严格分离的网格搜索区间")
    return boundary


def _normalise_lightgbm_grid(
    grid: dict[str, Sequence[int | float]] | None,
) -> dict[str, tuple[int | float, ...]]:
    supplied = grid or DEFAULT_LIGHTGBM_GRID
    expected = set(DEFAULT_LIGHTGBM_GRID)
    if set(supplied) != expected:
        raise ValueError(
            "LightGBM 网格必须且只能包含 n_estimators、learning_rate、"
            "num_leaves 和 min_child_samples"
        )
    normalized: dict[str, tuple[int | float, ...]] = {}
    for name, defaults in DEFAULT_LIGHTGBM_GRID.items():
        values = tuple(sorted(set(supplied[name])))
        if not values:
            raise ValueError(f"LightGBM 网格 {name} 不能为空")
        if any(float(value) <= 0 for value in values):
            raise ValueError(f"LightGBM 网格 {name} 必须全部大于 0")
        if isinstance(defaults[0], int):
            if any(float(value) != int(value) for value in values):
                raise ValueError(f"LightGBM 网格 {name} 必须使用整数")
            normalized[name] = tuple(int(value) for value in values)
        else:
            normalized[name] = tuple(float(value) for value in values)
    return normalized


def grid_search_lightgbm(
    flows: list[FlowRecord], *, train_fraction: float = 0.5,
    calibration_fraction: float = 0.2, target_fpr: float = 0.01,
    seed: int = 42,
    grid: dict[str, Sequence[int | float]] | None = None,
    source: str | None = None,
) -> dict[str, object]:
    """Tune LightGBM inside the outer training period without touching its test data."""
    try:
        import lightgbm
        from lightgbm import LGBMClassifier
    except ImportError as exc:
        raise ValueError(
            "LightGBM 网格搜索需要 LightGBM；请安装 comparison 可选依赖"
        ) from exc
    if not 0.0 <= target_fpr <= 0.5:
        raise ValueError("网格搜索目标 FPR 必须在 0 和 0.5 之间")

    normalized_grid = _normalise_lightgbm_grid(grid)
    outer = chronological_model_split(flows, train_fraction, calibration_fraction)
    outer_train = outer.train
    fit_end = max(1, min(len(outer_train) - 2, math.floor(len(outer_train) * 0.60)))
    fit_end = _strict_inner_boundary(outer_train, fit_end, 0)
    calibration_end = max(
        fit_end + 1,
        min(len(outer_train) - 1, math.floor(len(outer_train) * 0.80)),
    )
    calibration_end = _strict_inner_boundary(
        outer_train, calibration_end, fit_end,
    )
    inner_fit = outer_train[:fit_end]
    inner_calibration = outer_train[fit_end:calibration_end]
    inner_validation = outer_train[calibration_end:]

    fit_labels = [label_to_int(flow.label) for flow in inner_fit]
    calibration_labels = [label_to_int(flow.label) for flow in inner_calibration]
    validation_labels = [label_to_int(flow.label) for flow in inner_validation]
    if set(fit_labels) != {0, 1}:
        raise ValueError("网格搜索内部拟合区间必须同时包含正常和攻击样本")
    if 0 not in calibration_labels:
        raise ValueError("网格搜索内部校准区间必须包含正常样本")
    if set(validation_labels) != {0, 1}:
        raise ValueError("网格搜索内部验证区间必须同时包含正常和攻击样本")

    fit_matrix = _matrix(inner_fit)
    calibration_matrix = _matrix(inner_calibration)
    validation_matrix = _matrix(inner_validation)
    candidates: list[dict[str, object]] = []
    combinations = product(
        normalized_grid["n_estimators"],
        normalized_grid["learning_rate"],
        normalized_grid["num_leaves"],
        normalized_grid["min_child_samples"],
    )
    for n_estimators, learning_rate, num_leaves, min_child_samples in combinations:
        parameters = {
            "n_estimators": int(n_estimators),
            "learning_rate": float(learning_rate),
            "num_leaves": int(num_leaves),
            "min_child_samples": int(min_child_samples),
        }
        started = time.perf_counter()
        try:
            model = LGBMClassifier(
                objective="binary",
                random_state=seed,
                n_jobs=1,
                verbosity=-1,
                deterministic=True,
                force_col_wise=True,
                subsample=1.0,
                colsample_bytree=1.0,
                **parameters,
            )
            model.fit(fit_matrix, fit_labels)
            calibration_scores = [
                float(row[1]) for row in model.predict_proba(calibration_matrix)
            ]
            validation_scores = [
                float(row[1]) for row in model.predict_proba(validation_matrix)
            ]
            if not all(
                math.isfinite(value)
                for value in calibration_scores + validation_scores
            ):
                raise ValueError("候选模型产生了 NaN 或 Infinity 分数")
            benign_calibration_scores = [
                score for score, label in zip(calibration_scores, calibration_labels)
                if label == 0
            ]
            calibration = _calibrate_threshold(
                benign_calibration_scores, target_fpr,
            )
            validation = _metrics(
                validation_scores,
                validation_labels,
                float(calibration["threshold"]),
                [False] * len(validation_labels),
            )
            validation_fpr = float(validation["false_positive_rate"])
            candidates.append({
                **parameters,
                "status": "ok",
                "fit_seconds": round(time.perf_counter() - started, 6),
                "threshold": float(calibration["threshold"]),
                "inner_calibration_fpr": calibration[
                    "calibration_false_positive_rate"
                ],
                "validation_fpr": validation_fpr,
                "validation_precision": validation["precision"],
                "validation_recall": validation["recall"],
                "validation_f1": validation["f1"],
                "validation_auprc": round(
                    _average_precision(validation_scores, validation_labels), 6,
                ),
                "constraint_met": validation_fpr <= target_fpr + 1e-12,
            })
        except (ValueError, OverflowError, FloatingPointError) as exc:
            candidates.append({
                **parameters,
                "status": "infeasible",
                "fit_seconds": round(time.perf_counter() - started, 6),
                "error": str(exc),
                "constraint_met": False,
            })

    valid = [candidate for candidate in candidates if candidate["status"] == "ok"]
    if not valid:
        raise ValueError("所有 LightGBM 网格候选均不可用，未选择参数")
    feasible = [candidate for candidate in valid if candidate["constraint_met"]]

    def complexity_key(candidate: dict[str, object]) -> tuple[float, ...]:
        return (
            float(candidate["n_estimators"]) * float(candidate["num_leaves"]),
            -float(candidate["min_child_samples"]),
            float(candidate["learning_rate"]),
            float(candidate["n_estimators"]),
            float(candidate["num_leaves"]),
        )

    if feasible:
        selected = min(
            feasible,
            key=lambda candidate: (
                -float(candidate["validation_recall"]),
                -float(candidate["validation_auprc"]),
                *complexity_key(candidate),
            ),
        )
        selection_constraint_met = True
        selection_rule = (
            "maximum validation recall among candidates with validation FPR <= target; "
            "ties use higher AUPRC, then lower complexity"
        )
    else:
        selected = min(
            valid,
            key=lambda candidate: (
                float(candidate["validation_fpr"]) - target_fpr,
                -float(candidate["validation_recall"]),
                -float(candidate["validation_auprc"]),
                *complexity_key(candidate),
            ),
        )
        selection_constraint_met = False
        selection_rule = (
            "no candidate met the validation-FPR constraint; selected minimum FPR "
            "overshoot, then higher recall, higher AUPRC, and lower complexity"
        )

    best_params = {
        name: selected[name]
        for name in (
            "n_estimators", "learning_rate", "num_leaves", "min_child_samples"
        )
    }
    warning = None
    if not selection_constraint_met:
        warning = (
            "No candidate met the inner-validation FPR target; the selected fallback "
            "must not be described as satisfying the 1% constraint."
        )
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "method": "exhaustive_nested_chronological_grid_search",
        "library": {"name": "lightgbm", "version": lightgbm.__version__},
        "seed": seed,
        "target_false_positive_rate": target_fpr,
        "outer_split_access": {
            "training_rows_used": len(outer.train),
            "calibration_rows_reserved": len(outer.calibration),
            "test_rows_reserved": len(outer.test),
            "algorithmic_search_accessed_outer_calibration": False,
            "algorithmic_search_accessed_outer_test": False,
        },
        "inner_split": {
            "fit_rows": len(inner_fit),
            "calibration_rows": len(inner_calibration),
            "validation_rows": len(inner_validation),
            "fit_attack_rows": fit_labels.count(1),
            "calibration_benign_rows": calibration_labels.count(0),
            "validation_benign_rows": validation_labels.count(0),
            "validation_attack_rows": validation_labels.count(1),
            "fit_ends_at": inner_fit[-1].timestamp,
            "calibration_starts_at": inner_calibration[0].timestamp,
            "calibration_ends_at": inner_calibration[-1].timestamp,
            "validation_starts_at": inner_validation[0].timestamp,
        },
        "fixed_parameters": {
            "objective": "binary",
            "n_jobs": 1,
            "verbosity": -1,
            "deterministic": True,
            "force_col_wise": True,
            "subsample": 1.0,
            "colsample_bytree": 1.0,
        },
        "grid": {name: list(values) for name, values in normalized_grid.items()},
        "candidate_count": len(candidates),
        "valid_candidate_count": len(valid),
        "feasible_candidate_count": len(feasible),
        "selection_rule": selection_rule,
        "selection_constraint_met": selection_constraint_met,
        "best_params": best_params,
        "best_validation": {
            name: selected[name]
            for name in (
                "validation_fpr", "validation_precision", "validation_recall",
                "validation_f1", "validation_auprc", "threshold",
            )
        },
        "candidates": candidates,
        "warning": warning,
    }


def build_research_report(
    flows: list[FlowRecord], *, train_fraction: float = 0.5,
    calibration_fraction: float = 0.2,
    target_fprs: Sequence[float] = DEFAULT_TARGET_FPRS,
    seed: int = 42, source: str | None = None, batch_size: int = 256,
    logistic_epochs: int = 50, include_shap: bool = False,
    shap_background_size: int = 100, shap_summary_size: int = 2000,
    lightgbm_params: dict[str, int | float] | None = None,
    lightgbm_tuning: dict[str, object] | None = None,
) -> dict[str, object]:
    try:
        import sklearn
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:
        raise ValueError(
            "论文实验需要 scikit-learn；请运行 python -m pip install -e \".[comparison]\""
        ) from exc
    try:
        import lightgbm
        from lightgbm import LGBMClassifier
    except ImportError as exc:
        raise ValueError(
            "论文实验需要 LightGBM；请运行 python -m pip install -e \".[comparison]\""
        ) from exc
    normalized_targets = tuple(sorted({float(value) for value in target_fprs}))
    if not normalized_targets:
        raise ValueError("至少需要一个目标误报率")
    if batch_size < 1:
        raise ValueError("batch_size 必须至少为 1")
    if logistic_epochs < 1:
        raise ValueError("logistic_epochs 必须至少为 1")
    for target in normalized_targets:
        if not 0.0 <= target <= 0.5:
            raise ValueError("目标误报率必须在 0 和 0.5 之间")

    split = chronological_model_split(flows, train_fraction, calibration_fraction)
    default_lightgbm_params: dict[str, int | float] = {
        "n_estimators": 100,
        "learning_rate": 0.05,
        "num_leaves": 15,
        "min_child_samples": max(2, min(20, len(split.train) // 10)),
    }
    if lightgbm_tuning is not None:
        tuned = lightgbm_tuning.get("best_params")
        if not isinstance(tuned, dict):
            raise ValueError("LightGBM 网格搜索记录缺少 best_params")
        if lightgbm_params is None:
            lightgbm_params = tuned
        elif any(lightgbm_params.get(name) != tuned.get(name) for name in tuned):
            raise ValueError("LightGBM 参数与网格搜索胜出参数不一致")
    selected_lightgbm_params = {
        **default_lightgbm_params,
        **(lightgbm_params or {}),
    }
    if set(selected_lightgbm_params) != set(default_lightgbm_params):
        raise ValueError(
            "LightGBM 参数必须且只能包含 n_estimators、learning_rate、"
            "num_leaves 和 min_child_samples"
        )
    for name in ("n_estimators", "num_leaves", "min_child_samples"):
        value = selected_lightgbm_params[name]
        if float(value) != int(value) or int(value) < 1:
            raise ValueError(f"LightGBM 参数 {name} 必须为正整数")
        selected_lightgbm_params[name] = int(value)
    if float(selected_lightgbm_params["learning_rate"]) <= 0:
        raise ValueError("LightGBM 参数 learning_rate 必须大于 0")
    selected_lightgbm_params["learning_rate"] = float(
        selected_lightgbm_params["learning_rate"]
    )
    train_matrix = _matrix(split.train)
    calibration_matrix = _matrix(split.calibration)
    test_matrix = _matrix(split.test)
    train_labels = [label_to_int(flow.label) for flow in split.train]
    calibration_labels = [label_to_int(flow.label) for flow in split.calibration]
    test_labels = [label_to_int(flow.label) for flow in split.test]

    fit_started = time.perf_counter()
    trained = train_logistic_model(split.train, epochs=logistic_epochs, seed=seed)
    logistic_model = _linear_model(trained)
    logistic_fit_seconds = time.perf_counter() - fit_started

    def logistic_scorer(
        matrix: list[list[float]], _flows: list[FlowRecord],
    ) -> list[float]:
        return [
            logistic_model.predict_probability(dict(zip(FEATURE_NAMES, row)))
            for row in matrix
        ]

    fit_started = time.perf_counter()
    benign_matrix = [row for row, label in zip(train_matrix, train_labels) if label == 0]
    isolation_model = IsolationForest(
        n_estimators=100, contamination="auto", random_state=seed, n_jobs=1,
    )
    isolation_model.fit(benign_matrix)
    isolation_fit_seconds = time.perf_counter() - fit_started

    def isolation_scorer(
        matrix: list[list[float]], _flows: list[FlowRecord],
    ) -> list[float]:
        return [-float(value) for value in isolation_model.decision_function(matrix)]

    fit_started = time.perf_counter()
    lightgbm_model = LGBMClassifier(
        objective="binary",
        random_state=seed,
        n_jobs=1,
        verbosity=-1,
        deterministic=True,
        force_col_wise=True,
        subsample=1.0,
        colsample_bytree=1.0,
        **selected_lightgbm_params,
    )
    lightgbm_model.fit(train_matrix, train_labels)
    lightgbm_fit_seconds = time.perf_counter() - fit_started

    def lightgbm_scorer(
        matrix: list[list[float]], _flows: list[FlowRecord],
    ) -> list[float]:
        return [float(row[1]) for row in lightgbm_model.predict_proba(matrix)]

    def rule_scorer(
        _matrix: list[list[float]], selected_flows: list[FlowRecord],
    ) -> list[float]:
        return [
            max((hit.score for hit in evaluate_rules(flow)), default=0.0)
            for flow in selected_flows
        ]

    def hybrid_scorer(
        matrix: list[list[float]], selected_flows: list[FlowRecord],
    ) -> list[float]:
        model_scores = logistic_scorer(matrix, selected_flows)
        rule_scores = rule_scorer(matrix, selected_flows)
        return [
            min(max(max(0.70 * model_score + 0.30 * rule_score, 0.90 * rule_score), 0.0), 1.0)
            for model_score, rule_score in zip(model_scores, rule_scores)
        ]

    always_explainable = lambda selected: [True] * len(selected)
    never_explainable = lambda selected: [False] * len(selected)
    rule_explainable = lambda selected: [bool(evaluate_rules(flow)) for flow in selected]
    shared = {
        "calibration_matrix": calibration_matrix,
        "calibration_flows": split.calibration,
        "calibration_labels": calibration_labels,
        "test_matrix": test_matrix,
        "test_flows": split.test,
        "test_labels": test_labels,
        "target_fprs": normalized_targets,
        "batch_size": batch_size,
    }
    configurations = {
        "rule_only": _evaluate_configuration(
            name="rule_only", metadata={
                "algorithm": "transparent_project_rules", "version": "built-in",
                "training_rows": 0, "explanation_method": "triggered_rule_evidence",
            }, fit_seconds=0.0, scorer=rule_scorer,
            explanation_flags=rule_explainable, **shared,
        ),
        "logistic_regression": _evaluate_configuration(
            name="logistic_regression", metadata={
                "algorithm": "project_logistic_regression_sgd", "version": "built-in",
                "training_rows": len(split.train), "seed": seed,
                "epochs": logistic_epochs,
                "explanation_method": "exact_linear_logit_contributions",
            }, fit_seconds=logistic_fit_seconds, scorer=logistic_scorer,
            explanation_flags=always_explainable, **shared,
        ),
        "isolation_forest": _evaluate_configuration(
            name="isolation_forest", metadata={
                "algorithm": "sklearn_isolation_forest", "version": sklearn.__version__,
                "training_rows": len(benign_matrix), "training_scope": "benign_only",
                "n_estimators": 100, "seed": seed, "explanation_method": "none",
            }, fit_seconds=isolation_fit_seconds, scorer=isolation_scorer,
            explanation_flags=never_explainable, **shared,
        ),
        "lightgbm": _evaluate_configuration(
            name="lightgbm", metadata={
                "algorithm": "lightgbm_gbdt_classifier", "version": lightgbm.__version__,
                "training_rows": len(split.train), **selected_lightgbm_params,
                "deterministic": True, "force_col_wise": True,
                "subsample": 1.0, "colsample_bytree": 1.0, "seed": seed,
                "hyperparameter_selection": (
                    "nested_chronological_grid_search"
                    if lightgbm_tuning is not None else "fixed_configuration"
                ),
                "explanation_method": "none_without_optional_shap_analysis",
            }, fit_seconds=lightgbm_fit_seconds, scorer=lightgbm_scorer,
            explanation_flags=never_explainable, **shared,
        ),
        "hybrid_logistic_rules": _evaluate_configuration(
            name="hybrid_logistic_rules", metadata={
                "algorithm": "0.70_logistic_plus_0.30_rules_with_0.90_rule_floor",
                "version": "built-in", "training_rows": len(split.train), "seed": seed,
                "epochs": logistic_epochs,
                "explanation_method": "linear_contributions_and_rule_evidence",
            }, fit_seconds=logistic_fit_seconds, scorer=hybrid_scorer,
            explanation_flags=always_explainable, **shared,
        ),
    }
    shap_analysis = None
    if include_shap:
        lightgbm_test_scores = lightgbm_scorer(test_matrix, split.test)
        shap_analysis = _build_lightgbm_shap_analysis(
            model=lightgbm_model,
            calibration_matrix=calibration_matrix,
            calibration_labels=calibration_labels,
            test_matrix=test_matrix,
            test_flows=split.test,
            test_labels=test_labels,
            test_scores=lightgbm_test_scores,
            lightgbm_configuration=configurations["lightgbm"],
            background_size=shap_background_size,
            summary_size=shap_summary_size,
        )
        configurations["lightgbm"]["metadata"].update({
            "explanation_method": "tree_shap_interventional_probability",
            "shap_version": shap_analysis["library_version"],
            "shap_background_rows": shap_analysis["background_rows"],
        })
        for point in configurations["lightgbm"]["operating_points"].values():
            metrics = point["independent_test"]
            metrics["explanation_coverage"] = 1.0 if metrics["alerts"] else None
    primary_target = min(normalized_targets, key=lambda value: abs(value - 0.01))
    primary_key = f"{primary_target:g}"
    ranking = sorted(
        configurations,
        key=lambda config_name: (
            abs(
                float(configurations[config_name]["operating_points"][primary_key]["independent_test"]["false_positive_rate"])
                - primary_target
            ),
            -float(configurations[config_name]["operating_points"][primary_key]["independent_test"]["recall"]),
            -float(configurations[config_name]["operating_points"][primary_key]["independent_test"]["precision"]),
            float(configurations[config_name]["latency"]["p95_us_per_row"]),
        ),
    )
    warnings = [
        "排名仅使用最接近 1% 的目标 FPR，并按测试 FPR 与目标的距离、Recall、Precision、批量 P95 延迟排序。",
        "延迟来自当前机器的批量墙钟时间，不能直接代表生产部署性能。",
        (
            "Isolation Forest 当前没有逐告警本地解释；LightGBM 已对全部预测告警计算 Tree SHAP。"
            if include_shap else
            "Isolation Forest 与 LightGBM 当前没有逐告警本地解释；解释覆盖率按 0 记录。"
        ),
    ]
    if include_shap:
        warnings.append("SHAP 解释模型预测贡献，不代表网络特征与攻击之间存在因果关系。")
    if len(split.test) < 1000:
        warnings.append("独立测试集少于 1000 条；结果只能验证流程，不能作为论文结论。")
    if lightgbm_tuning is not None:
        warnings.append(
            "LightGBM 参数仅由外层训练时段内部的拟合、校准和验证区间选择；"
            "外层校准与独立测试区间未参与网格搜索。"
        )
        if not lightgbm_tuning.get("selection_constraint_met", False):
            warnings.append(
                "LightGBM 网格搜索没有候选满足内部验证 FPR 约束；已使用预先定义的回退规则。"
            )
    return {
        "schema_version": "1.2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "method": (
            "shared_chronological_train_calibration_test_fixed_fpr_with_nested_grid_search"
            if lightgbm_tuning is not None else
            "shared_chronological_train_calibration_test_fixed_fpr"
        ),
        "feature_names": FEATURE_NAMES,
        "seed": seed,
        "target_false_positive_rates": list(normalized_targets),
        "primary_target_false_positive_rate": primary_target,
        "split": {
            "train_rows": len(split.train),
            "calibration_rows": len(split.calibration),
            "test_rows": len(split.test),
            "train_benign_rows": train_labels.count(0),
            "train_attack_rows": train_labels.count(1),
            "test_benign_rows": test_labels.count(0),
            "test_attack_rows": test_labels.count(1),
            "train_ends_at": split.train[-1].timestamp,
            "calibration_starts_at": split.calibration[0].timestamp,
            "test_starts_at": split.test[0].timestamp,
            "strict_timestamp_boundaries": True,
        },
        "lightgbm_tuning": lightgbm_tuning,
        "configurations": configurations,
        "shap_analysis": shap_analysis,
        "ranking_at_primary_target": ranking,
        "warnings": warnings,
    }


def _atomic_write(path: Path, content: str, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise ValueError(f"输出文件已存在: {path}；如需替换请添加 --overwrite")
    if path.is_symlink():
        raise ValueError(f"输出文件不能是符号链接: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError(f"临时输出已存在，请先人工检查: {temporary}")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _metrics_csv(report: dict[str, object]) -> str:
    from io import StringIO

    handle = StringIO(newline="")
    fields = [
        "configuration", "target_fpr", "threshold", "calibration_fpr", "test_fpr",
        "precision", "recall", "f1", "average_precision", "recall_ci95_lower",
        "recall_ci95_upper", "test_fpr_ci95_lower", "test_fpr_ci95_upper",
        "explanation_coverage", "p95_us_per_row", "fit_seconds",
    ]
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    for name, configuration in report["configurations"].items():
        for target, point in configuration["operating_points"].items():
            calibration = point["calibration"]
            metrics = point["independent_test"]
            writer.writerow({
                "configuration": name,
                "target_fpr": target,
                "threshold": calibration["threshold"],
                "calibration_fpr": calibration["calibration_false_positive_rate"],
                "test_fpr": metrics["false_positive_rate"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "average_precision": metrics["average_precision"],
                "recall_ci95_lower": metrics["recall_ci95"]["lower"],
                "recall_ci95_upper": metrics["recall_ci95"]["upper"],
                "test_fpr_ci95_lower": metrics["false_positive_rate_ci95"]["lower"],
                "test_fpr_ci95_upper": metrics["false_positive_rate_ci95"]["upper"],
                "explanation_coverage": metrics["explanation_coverage"],
                "p95_us_per_row": configuration["latency"]["p95_us_per_row"],
                "fit_seconds": configuration["fit_seconds"],
            })
    return handle.getvalue()


def _shap_importance_csv(analysis: dict[str, object]) -> str:
    from io import StringIO

    handle = StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=["rank", "feature", "mean_absolute_shap"])
    writer.writeheader()
    for rank, item in enumerate(analysis["global_importance"], start=1):
        writer.writerow({"rank": rank, **item})
    return handle.getvalue()


def _shap_alerts_csv(analysis: dict[str, object]) -> str:
    from io import StringIO

    fields = [
        "test_row_index", "timestamp", "actual_label", "score", "base_value",
        "rank", "feature", "feature_value", "shap_value",
    ]
    handle = StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    for alert in analysis["alerts"]:
        for rank, contribution in enumerate(alert["top_contributions"], start=1):
            writer.writerow({
                "test_row_index": alert["test_row_index"],
                "timestamp": alert["timestamp"],
                "actual_label": alert["actual_label"],
                "score": alert["score"],
                "base_value": alert["base_value"],
                "rank": rank,
                **contribution,
            })
    return handle.getvalue()


def _save_figure(path: Path, figure: object, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise ValueError(f"输出文件已存在: {path}；如需替换请添加 --overwrite")
    if path.is_symlink():
        raise ValueError(f"输出文件不能是符号链接: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError(f"临时输出已存在，请先人工检查: {temporary}")
    try:
        figure.savefig(temporary, format="png", dpi=170, bbox_inches="tight")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_shap_plots(
    analysis: dict[str, object], directory: Path, *, overwrite: bool,
) -> list[Path]:
    _configure_matplotlib_cache()
    try:
        import matplotlib
        matplotlib.use("Agg", force=True)
        import matplotlib.pyplot as plt
        import numpy as np
        import shap
    except ImportError as exc:
        raise ValueError(
            "SHAP 图表需要 explainability 依赖；请运行 "
            'python -m pip install -e ".[explainability]"'
        ) from exc

    summary = analysis["summary"]
    explanation = shap.Explanation(
        values=np.asarray(summary["shap_values"], dtype=float),
        base_values=np.asarray(summary["base_values"], dtype=float),
        data=np.asarray(summary["feature_values"], dtype=float),
        feature_names=analysis["feature_names"],
    )
    paths: list[Path] = []

    plt.figure()
    shap.plots.beeswarm(
        explanation, max_display=min(10, len(FEATURE_NAMES)), show=False,
    )
    path = directory / "shap-beeswarm.png"
    _save_figure(path, plt.gcf(), overwrite)
    paths.append(path)
    plt.close(plt.gcf())

    plt.figure()
    shap.plots.bar(
        explanation.abs.mean(0), max_display=min(10, len(FEATURE_NAMES)), show=False,
    )
    path = directory / "shap-global-bar.png"
    _save_figure(path, plt.gcf(), overwrite)
    paths.append(path)
    plt.close(plt.gcf())

    for index, example in enumerate(analysis["local_examples"], start=1):
        local = shap.Explanation(
            values=np.asarray(example["shap_values"], dtype=float),
            base_values=float(example["base_value"]),
            data=np.asarray(example["feature_values"], dtype=float),
            feature_names=analysis["feature_names"],
        )
        plt.figure()
        shap.plots.waterfall(local, max_display=min(10, len(FEATURE_NAMES)), show=False)
        label = "tp" if int(example["actual_label"]) == 1 else "fp"
        path = directory / f"shap-local-{index:02d}-{label}.png"
        _save_figure(path, plt.gcf(), overwrite)
        paths.append(path)
        plt.close(plt.gcf())
    return paths


def _recall_svg(report: dict[str, object]) -> str:
    width, height = 900, 520
    left, top, chart_width, chart_height = 90, 50, 740, 370
    targets = [float(value) for value in report["target_false_positive_rates"]]
    colours = ["#2563eb", "#dc2626", "#059669", "#7c3aed", "#d97706"]
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="450" y="28" text-anchor="middle" font-family="Arial" font-size="20">Recall at fixed calibration FPR</text>',
    ]
    for tick in range(6):
        value = tick / 5
        y = top + chart_height * (1.0 - value)
        lines.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + chart_width}" y2="{y:.1f}" stroke="#e5e7eb"/>')
        lines.append(f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end" font-family="Arial" font-size="12">{value:.1f}</text>')
    x_positions = [
        left + (chart_width / 2 if len(targets) == 1 else index * chart_width / (len(targets) - 1))
        for index in range(len(targets))
    ]
    for x, target in zip(x_positions, targets):
        lines.append(f'<text x="{x:.1f}" y="{top + chart_height + 28}" text-anchor="middle" font-family="Arial" font-size="12">{target:g}</text>')
    lines.append(f'<text x="{left + chart_width / 2}" y="{height - 28}" text-anchor="middle" font-family="Arial" font-size="14">Target false-positive rate</text>')
    for model_index, (name, configuration) in enumerate(report["configurations"].items()):
        colour = colours[model_index % len(colours)]
        points = []
        for x, target in zip(x_positions, targets):
            recall = float(configuration["operating_points"][f"{target:g}"]["independent_test"]["recall"])
            y = top + chart_height * (1.0 - recall)
            points.append(f"{x:.1f},{y:.1f}")
            lines.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{colour}"/>')
        lines.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="{colour}" stroke-width="2"/>')
        legend_y = 70 + model_index * 24
        lines.append(f'<line x1="{left + chart_width + 12}" y1="{legend_y}" x2="{left + chart_width + 34}" y2="{legend_y}" stroke="{colour}" stroke-width="3"/>')
        lines.append(f'<text x="{left + chart_width + 40}" y="{legend_y + 4}" font-family="Arial" font-size="11">{escape(name)}</text>')
    lines.append('</svg>')
    return "\n".join(lines) + "\n"


def _latency_svg(report: dict[str, object]) -> str:
    width, height = 900, 520
    left, top, chart_width, chart_height = 90, 50, 740, 370
    configurations = list(report["configurations"].items())
    values = [float(item[1]["latency"]["p95_us_per_row"]) for item in configurations]
    maximum = max(values, default=1.0) or 1.0
    gap = chart_width / max(1, len(configurations))
    bar_width = gap * 0.62
    colours = ["#2563eb", "#dc2626", "#059669", "#7c3aed", "#d97706"]
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="450" y="28" text-anchor="middle" font-family="Arial" font-size="20">Batched P95 scoring latency</text>',
        f'<line x1="{left}" y1="{top + chart_height}" x2="{left + chart_width}" y2="{top + chart_height}" stroke="#111827"/>',
    ]
    for index, ((name, _), value) in enumerate(zip(configurations, values)):
        x = left + index * gap + (gap - bar_width) / 2
        bar_height = chart_height * value / maximum
        y = top + chart_height - bar_height
        colour = colours[index % len(colours)]
        lines.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{bar_height:.1f}" fill="{colour}"/>')
        lines.append(f'<text x="{x + bar_width / 2:.1f}" y="{y - 7:.1f}" text-anchor="middle" font-family="Arial" font-size="11">{value:.2f}</text>')
        lines.append(f'<text x="{x + bar_width / 2:.1f}" y="{top + chart_height + 20}" text-anchor="middle" font-family="Arial" font-size="10" transform="rotate(18 {x + bar_width / 2:.1f} {top + chart_height + 20})">{escape(name)}</text>')
    lines.append(f'<text x="22" y="{top + chart_height / 2}" text-anchor="middle" font-family="Arial" font-size="14" transform="rotate(-90 22 {top + chart_height / 2})">microseconds per row</text>')
    lines.append('</svg>')
    return "\n".join(lines) + "\n"


def _reproducibility_markdown(report: dict[str, object]) -> str:
    split = report["split"]
    targets = ", ".join(f"{value:g}" for value in report["target_false_positive_rates"])
    tuning = report.get("lightgbm_tuning")
    if tuning:
        params = tuning["best_params"]
        tuning_line = (
            "- LightGBM selection: nested chronological grid search inside outer training; "
            f"n_estimators={params['n_estimators']}, "
            f"learning_rate={params['learning_rate']}, "
            f"num_leaves={params['num_leaves']}, "
            f"min_child_samples={params['min_child_samples']}"
        )
    else:
        tuning_line = "- LightGBM selection: fixed configuration (no grid-search record)"
    return f"""# Research run record

This directory was generated by AI Firewall's `research-experiment` command.

- Source: `{report.get('source')}`
- Generated (UTC): `{report['generated_at']}`
- Seed: `{report['seed']}`
- Target calibration FPRs: `{targets}`
- Chronological split: {split['train_rows']} train / {split['calibration_rows']} calibration / {split['test_rows']} test rows
- Independent test labels: {split['test_benign_rows']} benign / {split['test_attack_rows']} attack rows
{tuning_line}

The calibration interval is used only to choose thresholds. Metrics are reported on the later independent test interval. If grid search is recorded, the outer calibration and independent test intervals did not participate in parameter selection. `metrics.csv` contains the tabular metrics, the SVG files contain editable figures, and the JSON report retains the complete machine-readable record.

Do not describe these results as production performance. Dataset provenance, class balance, temporal coverage, hardware, software versions, and any sampling limit must be reported in the paper.
"""


def _grid_search_candidates_csv(result: dict[str, object]) -> str:
    fields = (
        "n_estimators", "learning_rate", "num_leaves", "min_child_samples",
        "status", "constraint_met", "validation_fpr", "validation_precision",
        "validation_recall", "validation_f1", "validation_auprc",
        "inner_calibration_fpr", "threshold", "fit_seconds", "error",
    )
    rows = [
        {field: candidate.get(field) for field in fields}
        for candidate in result["candidates"]
    ]
    return _rows_csv(rows, fields)


def _grid_search_markdown(result: dict[str, object]) -> str:
    params = result["best_params"]
    metrics = result["best_validation"]
    split = result["inner_split"]
    constraint = "met" if result["selection_constraint_met"] else "not met"
    lines = [
        "# LightGBM nested chronological grid search",
        "",
        f"- Source: `{result.get('source')}`",
        f"- Generated (UTC): `{result['generated_at']}`",
        f"- Candidate configurations: {result['candidate_count']}",
        f"- Inner split: {split['fit_rows']} fit / {split['calibration_rows']} "
        f"threshold calibration / {split['validation_rows']} validation rows",
        f"- Selection target: validation FPR <= "
        f"{100.0 * float(result['target_false_positive_rate']):.2f}% ({constraint})",
        "- Outer calibration and independent test accessed during search: no",
        "",
        "## Selected parameters",
        "",
        f"- `n_estimators={params['n_estimators']}`",
        f"- `learning_rate={params['learning_rate']}`",
        f"- `num_leaves={params['num_leaves']}`",
        f"- `min_child_samples={params['min_child_samples']}`",
        "",
        "## Inner-validation result",
        "",
        f"- FPR: {100.0 * float(metrics['validation_fpr']):.4f}%",
        f"- Recall: {100.0 * float(metrics['validation_recall']):.4f}%",
        f"- F1: {100.0 * float(metrics['validation_f1']):.4f}%",
        f"- AUPRC: {100.0 * float(metrics['validation_auprc']):.4f}%",
        "",
        result["selection_rule"],
        "",
        "The selected parameters are refitted on the complete outer training period. "
        "The outer calibration period sets final thresholds, and the later outer test "
        "period is used only for final evaluation.",
        "",
    ]
    if result.get("warning"):
        lines.extend([f"Warning: {result['warning']}", ""])
    return "\n".join(lines)


def write_lightgbm_grid_search_bundle(
    result: dict[str, object], output_dir: str | Path, *, overwrite: bool = False,
) -> list[Path]:
    directory = Path(output_dir)
    if directory.exists() and not directory.is_dir():
        raise ValueError(f"输出路径不是目录: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    outputs = {
        "lightgbm-grid-search.json": json.dumps(
            result, ensure_ascii=False, indent=2,
        ) + "\n",
        "lightgbm-grid-search.csv": _grid_search_candidates_csv(result),
        "LIGHTGBM_GRID_SEARCH.md": _grid_search_markdown(result),
    }
    paths = [directory / name for name in outputs]
    existing = [path for path in paths if path.exists()]
    if existing and not overwrite:
        raise ValueError(
            "网格搜索输出已存在；如需替换请添加 --overwrite: "
            + ", ".join(str(path) for path in existing)
        )
    for path, content in zip(paths, outputs.values()):
        _atomic_write(path, content, overwrite)
    return paths


def write_research_bundle(
    report: dict[str, object], output_dir: str | Path, *, overwrite: bool = False,
) -> list[Path]:
    directory = Path(output_dir)
    if directory.exists() and not directory.is_dir():
        raise ValueError(f"输出路径不是目录: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    outputs = {
        "report.json": json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        "metrics.csv": _metrics_csv(report),
        "recall-at-fixed-fpr.svg": _recall_svg(report),
        "latency-p95.svg": _latency_svg(report),
        "REPRODUCIBILITY.md": _reproducibility_markdown(report),
    }
    shap_analysis = report.get("shap_analysis")
    plot_paths: list[Path] = []
    if shap_analysis:
        outputs.update({
            "shap-analysis.json": json.dumps(
                shap_analysis, ensure_ascii=False, indent=2,
            ) + "\n",
            "shap-global-importance.csv": _shap_importance_csv(shap_analysis),
            "shap-alert-top-contributions.csv": _shap_alerts_csv(shap_analysis),
        })
        plot_paths = [
            directory / "shap-beeswarm.png",
            directory / "shap-global-bar.png",
            *[
                directory / (
                    f"shap-local-{index:02d}-"
                    f"{'tp' if int(example['actual_label']) == 1 else 'fp'}.png"
                )
                for index, example in enumerate(
                    shap_analysis["local_examples"], start=1,
                )
            ],
        ]
    text_paths = [directory / name for name in outputs]
    paths = text_paths + plot_paths
    existing = [path for path in paths if path.exists()]
    if existing and not overwrite:
        raise ValueError(
            "实验输出已存在；如需替换请添加 --overwrite: "
            + ", ".join(str(path) for path in existing)
        )
    for path, content in zip(text_paths, outputs.values()):
        _atomic_write(path, content, overwrite)
    if shap_analysis:
        _write_shap_plots(shap_analysis, directory, overwrite=overwrite)
    return paths


def _descriptive_statistics(values: Sequence[float]) -> dict[str, object]:
    if not values:
        return {"n": 0, "mean": None, "sample_std": None, "min": None, "max": None}
    mean = sum(values) / len(values)
    sample_std = (
        math.sqrt(sum((value - mean) ** 2 for value in values) / (len(values) - 1))
        if len(values) > 1 else 0.0
    )
    return {
        "n": len(values),
        "mean": round(mean, 8),
        "sample_std": round(sample_std, 8),
        "min": round(min(values), 8),
        "max": round(max(values), 8),
    }


def aggregate_research_reports(
    reports: Sequence[dict[str, object]],
) -> dict[str, object]:
    if len(reports) < 2:
        raise ValueError("多随机种子汇总至少需要两份实验报告")
    seeds = [int(report["seed"]) for report in reports]
    if len(set(seeds)) != len(seeds):
        raise ValueError("多随机种子报告中存在重复 seed")
    reference = reports[0]
    reference_targets = reference["target_false_positive_rates"]
    reference_configs = set(reference["configurations"])
    reference_split = reference["split"]
    reference_source = reference.get("source")
    reference_tuning = reference.get("lightgbm_tuning")
    for report in reports[1:]:
        if report["target_false_positive_rates"] != reference_targets:
            raise ValueError("多随机种子报告的目标 FPR 不一致")
        if set(report["configurations"]) != reference_configs:
            raise ValueError("多随机种子报告的模型配置不一致")
        if report["split"] != reference_split:
            raise ValueError("多随机种子报告的时间切分不一致")
        if report.get("source") != reference_source:
            raise ValueError("多随机种子报告的数据来源不一致")
        if report.get("lightgbm_tuning") != reference_tuning:
            raise ValueError("多随机种子报告的 LightGBM 网格搜索记录不一致")

    metric_names = (
        "false_positive_rate", "precision", "recall", "f1",
        "average_precision",
    )
    rows: list[dict[str, object]] = []
    seed_values: list[dict[str, object]] = []
    for configuration_name in sorted(reference_configs):
        for target in reference_targets:
            target_key = f"{float(target):g}"
            for report in reports:
                configuration = report["configurations"][configuration_name]
                metrics = configuration["operating_points"][target_key]["independent_test"]
                seed_row = {
                    "seed": report["seed"],
                    "configuration": configuration_name,
                    "target_fpr": float(target),
                    **{name: metrics[name] for name in metric_names},
                    "explanation_coverage": metrics["explanation_coverage"],
                    "p95_us_per_row": configuration["latency"]["p95_us_per_row"],
                    "fit_seconds": configuration["fit_seconds"],
                }
                seed_values.append(seed_row)
            matching = [
                row for row in seed_values
                if row["configuration"] == configuration_name
                and row["target_fpr"] == float(target)
            ]
            for metric_name in (*metric_names, "p95_us_per_row", "fit_seconds"):
                values = [
                    float(row[metric_name]) for row in matching
                    if row[metric_name] is not None
                ]
                rows.append({
                    "configuration": configuration_name,
                    "target_fpr": float(target),
                    "metric": metric_name,
                    **_descriptive_statistics(values),
                })
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": reference_source,
        "method": "fixed_time_split_repeated_stochastic_training",
        "seeds": sorted(seeds),
        "seed_count": len(seeds),
        "target_false_positive_rates": reference_targets,
        "primary_target_false_positive_rate": reference[
            "primary_target_false_positive_rate"
        ],
        "split": reference_split,
        "lightgbm_tuning": reference_tuning,
        "statistics": rows,
        "seed_values": seed_values,
        "interpretation_warning": (
            "Variation across seeds measures algorithmic randomness on one fixed time split; "
            "it does not replace evaluation across additional temporal windows."
        ),
    }


def _rows_csv(rows: Sequence[dict[str, object]], fields: Sequence[str]) -> str:
    from io import StringIO

    handle = StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return handle.getvalue()


def _multiseed_markdown(aggregate: dict[str, object]) -> str:
    primary = float(aggregate["primary_target_false_positive_rate"])
    selected = [
        row for row in aggregate["statistics"]
        if float(row["target_fpr"]) == primary
        and row["metric"] in {
            "false_positive_rate", "precision", "recall", "f1", "average_precision",
        }
    ]
    by_key = {
        (row["configuration"], row["metric"]): row for row in selected
    }
    lines = [
        "# Multi-seed variation summary",
        "",
        f"Seeds: `{', '.join(str(seed) for seed in aggregate['seeds'])}`",
        f"Fixed chronological split: {aggregate['split']['train_rows']} train / "
        f"{aggregate['split']['calibration_rows']} calibration / "
        f"{aggregate['split']['test_rows']} test rows.",
        "",
        f"## Mean ± sample SD at target FPR {primary:g}",
        "",
        "| Configuration | Test FPR | Precision | Recall | F1 | AUPRC |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for configuration in sorted({row["configuration"] for row in selected}):
        cells = []
        for metric in (
            "false_positive_rate", "precision", "recall", "f1", "average_precision",
        ):
            item = by_key[(configuration, metric)]
            cells.append(f"{float(item['mean']):.4f} ± {float(item['sample_std']):.4f}")
        lines.append(f"| {configuration} | {' | '.join(cells)} |")
    lines.extend([
        "",
        "The time split and dataset sample are identical in every run. These standard "
        "deviations therefore quantify stochastic model instability only; they are not "
        "confidence intervals for deployment performance or temporal generalization.",
        "",
    ])
    return "\n".join(lines)


def write_multiseed_bundle(
    aggregate: dict[str, object], output_dir: str | Path, *, overwrite: bool = False,
) -> list[Path]:
    directory = Path(output_dir)
    if directory.exists() and not directory.is_dir():
        raise ValueError(f"输出路径不是目录: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    statistic_fields = (
        "configuration", "target_fpr", "metric", "n", "mean", "sample_std", "min", "max",
    )
    seed_fields = (
        "seed", "configuration", "target_fpr", "false_positive_rate", "precision",
        "recall", "f1", "average_precision", "explanation_coverage",
        "p95_us_per_row", "fit_seconds",
    )
    outputs = {
        "multiseed-aggregate.json": json.dumps(
            aggregate, ensure_ascii=False, indent=2,
        ) + "\n",
        "multiseed-statistics.csv": _rows_csv(
            aggregate["statistics"], statistic_fields,
        ),
        "multiseed-seed-values.csv": _rows_csv(
            aggregate["seed_values"], seed_fields,
        ),
        "MULTISEED_SUMMARY.md": _multiseed_markdown(aggregate),
    }
    tuning = aggregate.get("lightgbm_tuning")
    if tuning:
        outputs.update({
            "lightgbm-grid-search.json": json.dumps(
                tuning, ensure_ascii=False, indent=2,
            ) + "\n",
            "lightgbm-grid-search.csv": _grid_search_candidates_csv(tuning),
            "LIGHTGBM_GRID_SEARCH.md": _grid_search_markdown(tuning),
        })
    paths = [directory / name for name in outputs]
    existing = [path for path in paths if path.exists()]
    if existing and not overwrite:
        raise ValueError(
            "实验输出已存在；如需替换请添加 --overwrite: "
            + ", ".join(str(path) for path in existing)
        )
    for path, content in zip(paths, outputs.values()):
        _atomic_write(path, content, overwrite)
    return paths
