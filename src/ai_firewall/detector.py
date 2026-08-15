from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .features import extract_features
from .model import LinearModel
from .rules import RuleHit, evaluate_rules
from .schema import FlowRecord


@dataclass(frozen=True)
class DetectionResult:
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    model_score: float
    rule_score: float
    risk_score: float
    severity: str
    is_alert: bool
    reasons: list[str]
    rule_ids: list[str]
    rule_evidence: list[dict[str, object]] = field(default_factory=list)
    top_features: list[dict[str, object]] = field(default_factory=list)
    model_algorithm: str = "unknown"
    model_version: str = "unversioned"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class HybridDetector:
    """Combines a small statistical model with transparent safety rules."""

    def __init__(self, model: LinearModel, threshold: float = 0.60):
        if not 0.0 < threshold < 1.0:
            raise ValueError("threshold 必须在 0 和 1 之间")
        self.model = model
        self.threshold = threshold

    def analyze(self, flow: FlowRecord) -> DetectionResult:
        features = extract_features(flow)
        model_score = self.model.predict_probability(features)
        hits: list[RuleHit] = evaluate_rules(flow)
        rule_score = max((hit.score for hit in hits), default=0.0)

        # A strong rule must remain visible even if a model is unfamiliar with it.
        combined = max(0.70 * model_score + 0.30 * rule_score, rule_score * 0.90)
        risk_score = min(max(combined, 0.0), 1.0)

        if risk_score >= 0.85:
            severity = "critical"
        elif risk_score >= 0.70:
            severity = "high"
        elif risk_score >= self.threshold:
            severity = "medium"
        else:
            severity = "info"

        reasons = [hit.reason for hit in hits]
        if not reasons and model_score >= self.threshold:
            reasons.append("统计模型发现流量特征偏离正常模式")
        if not reasons:
            reasons.append("未发现达到告警阈值的异常")

        return DetectionResult(
            timestamp=flow.timestamp,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            model_score=round(model_score, 4),
            rule_score=round(rule_score, 4),
            risk_score=round(risk_score, 4),
            severity=severity,
            is_alert=risk_score >= self.threshold,
            reasons=reasons,
            rule_ids=[hit.rule_id for hit in hits],
            rule_evidence=[{
                "rule_id": hit.rule_id,
                "score": round(hit.score, 4),
                "reason": hit.reason,
            } for hit in hits],
            top_features=self.model.explain(features),
            model_algorithm=self.model.algorithm,
            model_version=self.model.model_version,
        )
