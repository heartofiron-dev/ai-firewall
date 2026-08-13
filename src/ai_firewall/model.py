from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

from .features import FEATURE_NAMES


@dataclass(frozen=True)
class LinearModel:
    feature_names: list[str]
    means: list[float]
    scales: list[float]
    weights: list[float]
    bias: float
    metadata: dict[str, object]

    @classmethod
    def load(cls, path: str | Path) -> "LinearModel":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        names = list(data["feature_names"])
        if names != FEATURE_NAMES:
            raise ValueError("模型特征与当前程序版本不兼容")
        return cls(
            feature_names=names,
            means=[float(v) for v in data["means"]],
            scales=[max(float(v), 1e-9) for v in data["scales"]],
            weights=[float(v) for v in data["weights"]],
            bias=float(data["bias"]),
            metadata=dict(data.get("metadata", {})),
        )

    def predict_probability(self, features: dict[str, float]) -> float:
        values = [features[name] for name in self.feature_names]
        standardized = [
            (value - mean) / scale
            for value, mean, scale in zip(values, self.means, self.scales)
        ]
        logit = self.bias + sum(w * x for w, x in zip(self.weights, standardized))
        logit = max(min(logit, 40.0), -40.0)
        return 1.0 / (1.0 + math.exp(-logit))

