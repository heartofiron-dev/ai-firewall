from __future__ import annotations

import json
import math
import random
from datetime import datetime, timezone
from pathlib import Path

from .features import FEATURE_NAMES, extract_features
from .schema import FlowRecord


ATTACK_LABELS = {"1", "attack", "malicious", "anomaly", "true", "yes"}
BENIGN_LABELS = {"0", "benign", "normal", "false", "no"}


def label_to_int(label: str | None) -> int:
    normalized = (label or "").strip().lower()
    if normalized in ATTACK_LABELS:
        return 1
    if normalized in BENIGN_LABELS:
        return 0
    raise ValueError(f"不支持的标签: {label!r}")


def train_logistic_model(
    flows: list[FlowRecord], epochs: int = 800, learning_rate: float = 0.08,
    seed: int = 42,
) -> dict[str, object]:
    if len(flows) < 4:
        raise ValueError("至少需要 4 条带标签记录")
    labels = [label_to_int(flow.label) for flow in flows]
    rows = [extract_features(flow) for flow in flows]
    return train_logistic_features(
        rows, labels, epochs=epochs, learning_rate=learning_rate, seed=seed,
    )


def train_logistic_features(
    feature_rows: list[dict[str, float]], labels: list[int], epochs: int = 800,
    learning_rate: float = 0.08, seed: int = 42,
) -> dict[str, object]:
    """Train the built-in model from reviewed, metadata-free feature rows."""
    if len(feature_rows) < 4 or len(feature_rows) != len(labels):
        raise ValueError("至少需要 4 条且特征与标签数量必须一致")
    if epochs < 1 or not 0.0 < learning_rate <= 1.0:
        raise ValueError("epochs 必须大于 0，learning_rate 必须在 0 和 1 之间")
    if any(label not in {0, 1} for label in labels):
        raise ValueError("训练标签只能是 0 或 1")
    if len(set(labels)) < 2:
        raise ValueError("训练数据必须同时包含正常和攻击样本")

    rows = []
    for index, item in enumerate(feature_rows, start=1):
        if set(item) != set(FEATURE_NAMES):
            raise ValueError(f"第 {index} 条特征与当前模型不兼容")
        try:
            row = [float(item[name]) for name in FEATURE_NAMES]
        except (TypeError, ValueError) as exc:
            raise ValueError(f"第 {index} 条特征不是有效数字") from exc
        if not all(math.isfinite(value) for value in row):
            raise ValueError(f"第 {index} 条特征包含非有限值")
        rows.append(row)
    count = len(rows)
    means = [sum(row[i] for row in rows) / count for i in range(len(FEATURE_NAMES))]
    scales = []
    for i, mean in enumerate(means):
        variance = sum((row[i] - mean) ** 2 for row in rows) / count
        scales.append(max(math.sqrt(variance), 1.0))
    samples = [[(value - means[i]) / scales[i] for i, value in enumerate(row)] for row in rows]

    rng = random.Random(seed)
    weights = [rng.uniform(-0.01, 0.01) for _ in FEATURE_NAMES]
    bias = 0.0
    order = list(range(count))

    for _ in range(epochs):
        rng.shuffle(order)
        for index in order:
            x = samples[index]
            y = labels[index]
            logit = max(min(bias + sum(w * v for w, v in zip(weights, x)), 40), -40)
            prediction = 1.0 / (1.0 + math.exp(-logit))
            error = prediction - y
            for j in range(len(weights)):
                weights[j] -= learning_rate * (error * x[j] + 0.0005 * weights[j])
            bias -= learning_rate * error

    return {
        "feature_names": FEATURE_NAMES,
        "means": means,
        "scales": scales,
        "weights": weights,
        "bias": bias,
        "metadata": {
            "algorithm": "logistic_regression_sgd",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "training_rows": count,
            "attack_rows": sum(labels),
            "benign_rows": count - sum(labels),
            "epochs": epochs,
            "learning_rate": learning_rate,
        },
    }


def save_model(model: dict[str, object], path: str | Path) -> None:
    Path(path).write_text(json.dumps(model, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
