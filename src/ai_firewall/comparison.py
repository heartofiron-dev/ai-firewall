from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .features import FEATURE_NAMES, extract_features
from .model import LinearModel
from .schema import FlowRecord
from .training import label_to_int, train_logistic_model


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
class ComparisonSplit:
    train: list[FlowRecord]
    calibration: list[FlowRecord]
    test: list[FlowRecord]


def chronological_model_split(
    flows: list[FlowRecord], train_fraction: float = 0.5,
    calibration_fraction: float = 0.2,
) -> ComparisonSplit:
    if not 0.2 <= train_fraction <= 0.7:
        raise ValueError("train_fraction 必须在 0.2 和 0.7 之间")
    if not 0.1 <= calibration_fraction <= 0.4:
        raise ValueError("calibration_fraction 必须在 0.1 和 0.4 之间")
    if train_fraction + calibration_fraction > 0.9:
        raise ValueError("训练与校准比例之和不能超过 0.9")
    if len(flows) < 20:
        raise ValueError("模型对比至少需要 20 条按时间排序的带标签记录")

    ordered = sorted(flows, key=lambda flow: _timestamp(flow.timestamp))
    train_end = max(1, min(len(ordered) - 2, math.floor(len(ordered) * train_fraction)))
    calibration_end = max(
        train_end + 1,
        min(len(ordered) - 1, math.floor(len(ordered) * (train_fraction + calibration_fraction))),
    )
    split = ComparisonSplit(
        train=ordered[:train_end],
        calibration=ordered[train_end:calibration_end],
        test=ordered[calibration_end:],
    )
    train_labels = {label_to_int(flow.label) for flow in split.train}
    test_labels = {label_to_int(flow.label) for flow in split.test}
    if train_labels != {0, 1}:
        raise ValueError("训练时间段必须同时包含正常和攻击样本")
    if not any(label_to_int(flow.label) == 0 for flow in split.calibration):
        raise ValueError("阈值校准时间段必须包含正常样本")
    if test_labels != {0, 1}:
        raise ValueError("独立测试时间段必须同时包含正常和攻击样本")
    return split


def _matrix(flows: list[FlowRecord]) -> list[list[float]]:
    rows: list[list[float]] = []
    for index, flow in enumerate(flows):
        features = extract_features(flow)
        row = [float(features[name]) for name in FEATURE_NAMES]
        if not all(math.isfinite(value) for value in row):
            raise ValueError(f"第 {index + 1} 条记录含有 NaN 或 Infinity 特征")
        rows.append(row)
    return rows


def _calibrate_threshold(benign_scores: list[float], target_fpr: float) -> dict[str, float | int | bool]:
    if not 0.0 <= target_fpr <= 0.5:
        raise ValueError("target_fpr 必须在 0 和 0.5 之间")
    if not benign_scores:
        raise ValueError("阈值校准时间段没有正常样本")
    if not all(math.isfinite(score) for score in benign_scores):
        raise ValueError("模型产生了非有限校准分数")

    candidates = sorted({math.nextafter(score, math.inf) for score in benign_scores})
    selected = candidates[-1]
    achieved = 0.0
    for candidate in candidates:
        empirical = sum(score >= candidate for score in benign_scores) / len(benign_scores)
        if empirical <= target_fpr:
            selected = candidate
            achieved = empirical
            break
    return {
        "threshold": selected,
        "target_false_positive_rate": target_fpr,
        "calibration_false_positive_rate": achieved,
        "calibration_benign_rows": len(benign_scores),
        "target_met": achieved <= target_fpr,
    }


def _metrics(scores: list[float], labels: list[int], threshold: float) -> dict[str, float | int]:
    if len(scores) != len(labels):
        raise ValueError("模型分数数量与测试标签数量不一致")
    tp = fp = tn = fn = 0
    for score, actual in zip(scores, labels):
        predicted = int(score >= threshold)
        tp += predicted == 1 and actual == 1
        fp += predicted == 1 and actual == 0
        tn += predicted == 0 and actual == 0
        fn += predicted == 0 and actual == 1
    return {
        "rows": len(labels),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": round(tp / (tp + fp), 6) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 6) if tp + fn else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 6) if fp + tn else 0.0,
    }


def _linear_model(data: dict[str, object]) -> LinearModel:
    return LinearModel(
        feature_names=list(data["feature_names"]),
        means=[float(value) for value in data["means"]],
        scales=[float(value) for value in data["scales"]],
        weights=[float(value) for value in data["weights"]],
        bias=float(data["bias"]),
        metadata=dict(data["metadata"]),
    )


def _evaluate_model(
    name: str, fit: Callable[[], tuple[Callable[[list[list[float]]], list[float]], dict[str, object]]],
    calibration_matrix: list[list[float]], calibration_labels: list[int],
    test_matrix: list[list[float]], test_labels: list[int], target_fpr: float,
) -> dict[str, object]:
    fit_started = time.perf_counter()
    scorer, metadata = fit()
    fit_seconds = time.perf_counter() - fit_started

    score_started = time.perf_counter()
    calibration_scores = scorer(calibration_matrix)
    test_scores = scorer(test_matrix)
    score_seconds = time.perf_counter() - score_started
    if not all(math.isfinite(score) for score in calibration_scores + test_scores):
        raise ValueError(f"模型 {name} 产生了 NaN 或 Infinity 分数")
    benign_scores = [
        score for score, label in zip(calibration_scores, calibration_labels) if label == 0
    ]
    calibration = _calibrate_threshold(benign_scores, target_fpr)
    threshold = float(calibration["threshold"])
    return {
        "name": name,
        "metadata": metadata,
        "fit_seconds": round(fit_seconds, 6),
        "score_seconds": round(score_seconds, 6),
        "calibration": {
            **calibration,
            "threshold": threshold,
            "calibration_false_positive_rate": round(
                float(calibration["calibration_false_positive_rate"]), 6
            ),
        },
        "independent_test": _metrics(test_scores, test_labels, threshold),
    }


def build_model_comparison(
    flows: list[FlowRecord], *, train_fraction: float = 0.5,
    calibration_fraction: float = 0.2, target_fpr: float = 0.01,
    seed: int = 42, source: str | None = None,
) -> dict[str, object]:
    try:
        import sklearn
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:
        raise ValueError(
            "模型对比需要 scikit-learn；请运行 python -m pip install -e \".[comparison]\""
        ) from exc
    try:
        import lightgbm
        from lightgbm import LGBMClassifier
    except ImportError as exc:
        raise ValueError(
            "模型对比需要 LightGBM；请运行 python -m pip install -e \".[comparison]\""
        ) from exc

    split = chronological_model_split(flows, train_fraction, calibration_fraction)
    train_matrix = _matrix(split.train)
    calibration_matrix = _matrix(split.calibration)
    test_matrix = _matrix(split.test)
    train_labels = [label_to_int(flow.label) for flow in split.train]
    calibration_labels = [label_to_int(flow.label) for flow in split.calibration]
    test_labels = [label_to_int(flow.label) for flow in split.test]

    def fit_logistic() -> tuple[Callable[[list[list[float]]], list[float]], dict[str, object]]:
        trained = train_logistic_model(split.train, seed=seed)
        model = _linear_model(trained)

        def score(matrix: list[list[float]]) -> list[float]:
            return [
                model.predict_probability(dict(zip(FEATURE_NAMES, row))) for row in matrix
            ]

        return score, {
            "algorithm": "project_logistic_regression_sgd",
            "version": "built-in",
            "training_rows": len(split.train),
            "seed": seed,
        }

    def fit_isolation() -> tuple[Callable[[list[list[float]]], list[float]], dict[str, object]]:
        benign_matrix = [row for row, label in zip(train_matrix, train_labels) if label == 0]
        model = IsolationForest(
            n_estimators=100, contamination="auto", random_state=seed, n_jobs=1,
        )
        model.fit(benign_matrix)

        def score(matrix: list[list[float]]) -> list[float]:
            return [-float(value) for value in model.decision_function(matrix)]

        return score, {
            "algorithm": "sklearn_isolation_forest",
            "version": sklearn.__version__,
            "training_rows": len(benign_matrix),
            "training_scope": "benign_only",
            "n_estimators": 100,
            "seed": seed,
        }

    def fit_lightgbm() -> tuple[Callable[[list[list[float]]], list[float]], dict[str, object]]:
        model = LGBMClassifier(
            objective="binary", n_estimators=100, learning_rate=0.05,
            num_leaves=15, min_child_samples=max(2, min(20, len(split.train) // 10)),
            random_state=seed, n_jobs=1, verbosity=-1,
        )
        model.fit(train_matrix, train_labels)

        def score(matrix: list[list[float]]) -> list[float]:
            probabilities = model.predict_proba(matrix)
            return [float(row[1]) for row in probabilities]

        return score, {
            "algorithm": "lightgbm_gbdt_classifier",
            "version": lightgbm.__version__,
            "training_rows": len(split.train),
            "n_estimators": 100,
            "num_leaves": 15,
            "seed": seed,
        }

    models = {
        "logistic_regression": _evaluate_model(
            "logistic_regression", fit_logistic,
            calibration_matrix, calibration_labels, test_matrix, test_labels, target_fpr,
        ),
        "isolation_forest": _evaluate_model(
            "isolation_forest", fit_isolation,
            calibration_matrix, calibration_labels, test_matrix, test_labels, target_fpr,
        ),
        "lightgbm": _evaluate_model(
            "lightgbm", fit_lightgbm,
            calibration_matrix, calibration_labels, test_matrix, test_labels, target_fpr,
        ),
    }
    ranking = sorted(
        models,
        key=lambda model_name: (
            float(models[model_name]["independent_test"]["false_positive_rate"]),
            -float(models[model_name]["independent_test"]["recall"]),
            -float(models[model_name]["independent_test"]["precision"]),
        ),
    )
    warnings = [
        "该排名先按测试 FPR、再按 Recall 和 Precision 排序，不代表生产环境优劣。",
    ]
    if len(split.test) < 1000:
        warnings.append("独立测试集少于 1000 条；指标只能验证流程，不能作为生产结论。")
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "method": "shared_chronological_train_calibration_test",
        "feature_names": FEATURE_NAMES,
        "seed": seed,
        "target_false_positive_rate": target_fpr,
        "split": {
            "train_rows": len(split.train),
            "calibration_rows": len(split.calibration),
            "test_rows": len(split.test),
            "train_ends_at": split.train[-1].timestamp,
            "calibration_starts_at": split.calibration[0].timestamp,
            "test_starts_at": split.test[0].timestamp,
        },
        "models": models,
        "ranking": ranking,
        "warnings": warnings,
    }


def write_comparison_report(report: dict[str, object], path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
