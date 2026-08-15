from __future__ import annotations

import hashlib
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

    @property
    def algorithm(self) -> str:
        return str(self.metadata.get("algorithm") or "linear_model")

    @property
    def model_version(self) -> str:
        configured = self.metadata.get("version")
        if configured:
            return str(configured)
        payload = json.dumps(
            {
                "feature_names": self.feature_names,
                "means": self.means,
                "scales": self.scales,
                "weights": self.weights,
                "bias": self.bias,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(payload).hexdigest()[:12]}"

    def explain(
        self, features: dict[str, float], limit: int = 3,
    ) -> list[dict[str, object]]:
        """Return the strongest exact linear-logit contributions."""
        if limit < 1:
            raise ValueError("limit 必须至少为 1")
        contributions = []
        for name, mean, scale, weight in zip(
            self.feature_names, self.means, self.scales, self.weights,
        ):
            value = float(features[name])
            standardized = (value - mean) / scale
            contribution = weight * standardized
            contributions.append({
                "name": name,
                "value": round(value, 6),
                "standardized_value": round(standardized, 6),
                "weight": round(weight, 6),
                "contribution": round(contribution, 6),
                "direction": "raises_risk" if contribution >= 0 else "lowers_risk",
            })
        contributions.sort(
            key=lambda item: (-abs(float(item["contribution"])), str(item["name"])),
        )
        return contributions[:limit]
