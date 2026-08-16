from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .dashboard import ALERT_ID_PATTERN, alert_fingerprint
from .features import FEATURE_NAMES, extract_features
from .io import read_flows
from .training import label_to_int, train_logistic_features


MAX_REVIEW_BYTES = 20 * 1024 * 1024
DECISIONS = {"approve", "reject"}


def _safe_jsonl(path: Path, *, may_not_exist: bool = False) -> list[dict[str, Any]]:
    if path.is_symlink():
        raise ValueError(f"拒绝符号链接: {path}")
    if not path.exists():
        if may_not_exist:
            return []
        raise ValueError(f"文件不存在: {path}")
    if path.suffix.casefold() != ".jsonl":
        raise ValueError(f"审核文件必须使用 .jsonl: {path}")
    if path.stat().st_size > MAX_REVIEW_BYTES:
        raise ValueError(f"审核文件超过 20 MiB 安全上限: {path}")
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path} 第 {number} 行不是完整 JSON") from exc
            if not isinstance(item, dict):
                raise ValueError(f"{path} 第 {number} 行必须是 JSON 对象")
            rows.append(item)
    return rows


def _validated_features(item: object) -> dict[str, float]:
    if not isinstance(item, dict) or set(item) != set(FEATURE_NAMES):
        raise ValueError("告警缺少完整、兼容的 feature_snapshot；请用 v1.0+ 重新生成告警")
    result: dict[str, float] = {}
    for name in FEATURE_NAMES:
        try:
            value = float(item[name])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"反馈特征 {name} 不是有效数字") from exc
        if not math.isfinite(value):
            raise ValueError(f"反馈特征 {name} 不是有限值")
        result[name] = value
    return result


def review_feedback(
    alerts_path: str | Path,
    pending_path: str | Path,
    reviewed_path: str | Path,
    *,
    decision: str,
    alert_ids: set[str] | None = None,
    reviewer: str = "local-user",
) -> dict[str, int]:
    """Append explicit human decisions with metadata-free training snapshots."""
    if decision not in DECISIONS:
        raise ValueError("decision 必须是 approve 或 reject")
    if len(reviewer) > 80 or not reviewer.strip():
        raise ValueError("reviewer 必须为 1 到 80 个字符")
    alerts = Path(alerts_path)
    pending = Path(pending_path)
    reviewed = Path(reviewed_path)
    resolved = {alerts.resolve(), pending.resolve(), reviewed.resolve()}
    if len(resolved) != 3:
        raise ValueError("告警、待审核队列与审核账本必须是三个不同文件")
    if reviewed.is_symlink():
        raise ValueError("拒绝符号链接审核账本")
    if reviewed.exists() and reviewed.stat().st_size > MAX_REVIEW_BYTES:
        raise ValueError("审核账本超过 20 MiB 安全上限")

    alert_map: dict[str, dict[str, Any]] = {}
    for item in _safe_jsonl(alerts):
        alert_map[alert_fingerprint(item)] = item
    pending_rows = _safe_jsonl(pending)
    reviewed_rows = _safe_jsonl(reviewed, may_not_exist=True)
    already = {
        str(row.get("alert_id")) for row in reviewed_rows
        if ALERT_ID_PATTERN.fullmatch(str(row.get("alert_id", "")))
    }
    pending_map = {
        str(row.get("alert_id")): row for row in pending_rows
        if row.get("review_status") == "pending"
        and ALERT_ID_PATTERN.fullmatch(str(row.get("alert_id", "")))
    }
    selected = set(pending_map) if alert_ids is None else set(alert_ids)
    invalid = {item for item in selected if not ALERT_ID_PATTERN.fullmatch(item)}
    if invalid:
        raise ValueError("存在格式无效的 alert_id")
    missing = selected - set(pending_map)
    if missing:
        raise ValueError(f"待审核队列中找不到 {len(missing)} 个 alert_id")

    entries = []
    now = datetime.now(timezone.utc).isoformat()
    for alert_id in sorted(selected - already):
        pending_item = pending_map[alert_id]
        alert = alert_map.get(alert_id)
        if alert is None:
            raise ValueError(f"告警源中找不到 {alert_id}；不能审核脱离来源的反馈")
        entry: dict[str, Any] = {
            "schema_version": "1.0",
            "alert_id": alert_id,
            "feedback_label": str(pending_item.get("label") or ""),
            "decision": decision,
            "reviewer": reviewer.strip(),
            "reviewed_at": now,
            "source_model_version": str(alert.get("model_version") or "unknown"),
        }
        if decision == "approve":
            if entry["feedback_label"] != "false_positive":
                raise ValueError("当前版本只允许批准 false_positive 反馈")
            entry["training_label"] = 0
            entry["features"] = _validated_features(alert.get("feature_snapshot"))
        entries.append(entry)

    if entries:
        reviewed.parent.mkdir(parents=True, exist_ok=True)
        with reviewed.open("a", encoding="utf-8") as handle:
            for entry in entries:
                handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
    return {
        "pending": len(pending_map),
        "selected": len(selected),
        "written": len(entries),
        "already_reviewed": len(selected & already),
    }


def build_feedback_model(
    base_csv: str | Path,
    reviewed_path: str | Path,
    *,
    epochs: int = 800,
    learning_rate: float = 0.08,
    max_feedback_fraction: float = 0.20,
) -> dict[str, object]:
    """Retrain only from approved review records plus an authorized base set."""
    if not 0.0 < max_feedback_fraction <= 0.5:
        raise ValueError("max_feedback_fraction 必须在 0 和 0.5 之间")
    base = read_flows(base_csv)
    base_features = [extract_features(flow) for flow in base]
    labels = [label_to_int(flow.label) for flow in base]
    ledger = Path(reviewed_path)
    rows = _safe_jsonl(ledger)
    approved = [row for row in rows if row.get("decision") == "approve"]
    if not approved:
        raise ValueError("审核账本中没有已批准反馈")
    ids = [str(row.get("alert_id") or "") for row in approved]
    if len(ids) != len(set(ids)):
        raise ValueError("审核账本包含重复的已批准 alert_id")
    allowed = max(1, int(len(base) * max_feedback_fraction))
    if len(approved) > allowed:
        raise ValueError(
            f"已批准反馈 {len(approved)} 条超过基线数据的 {max_feedback_fraction:.0%} 上限 {allowed}；"
            "请扩充并重新审核基线数据，避免反馈投毒"
        )
    feedback_features = [_validated_features(row.get("features")) for row in approved]
    feedback_labels = []
    for row in approved:
        label = row.get("training_label")
        if label not in {0, 1}:
            raise ValueError("审核账本包含无效 training_label")
        feedback_labels.append(int(label))
    model = train_logistic_features(
        base_features + feedback_features,
        labels + feedback_labels,
        epochs=epochs,
        learning_rate=learning_rate,
    )
    digest = hashlib.sha256(ledger.read_bytes()).hexdigest()
    metadata = dict(model["metadata"])
    metadata.update({
        "base_training_rows": len(base),
        "approved_feedback_rows": len(approved),
        "feedback_fraction": round(len(approved) / len(base), 6),
        "review_ledger_sha256": digest,
        "reviewed_alert_ids_sha256": hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest(),
        "training_policy": "explicitly_approved_feedback_only",
    })
    model["metadata"] = metadata
    return model
