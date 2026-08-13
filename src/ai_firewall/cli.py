from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detector import HybridDetector
from .io import read_flows, write_jsonl
from .model import LinearModel
from .training import label_to_int, save_model, train_logistic_model


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL = PROJECT_ROOT / "models" / "baseline.json"
DEFAULT_SAMPLE = PROJECT_ROOT / "data" / "sample_flows.csv"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-firewall",
        description="AI 防火墙 MVP：离线分析、训练与评估网络流记录。",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="分析仓库自带的安全演示数据")
    demo.add_argument("--model", default=str(DEFAULT_MODEL))
    demo.add_argument("--threshold", type=float, default=0.60)

    analyze = sub.add_parser("analyze", help="分析 CSV 网络流记录")
    analyze.add_argument("input")
    analyze.add_argument("--model", default=str(DEFAULT_MODEL))
    analyze.add_argument("--threshold", type=float, default=0.60)
    analyze.add_argument("--output", default="alerts.jsonl")
    analyze.add_argument("--all", action="store_true", help="输出全部结果，而不仅是告警")

    train = sub.add_parser("train", help="用带标签 CSV 训练逻辑回归模型")
    train.add_argument("input")
    train.add_argument("--output", default="models/trained-model.json")
    train.add_argument("--epochs", type=int, default=800)
    train.add_argument("--learning-rate", type=float, default=0.08)

    evaluate = sub.add_parser("evaluate", help="在带标签 CSV 上计算检测指标")
    evaluate.add_argument("input")
    evaluate.add_argument("--model", default=str(DEFAULT_MODEL))
    evaluate.add_argument("--threshold", type=float, default=0.60)
    return parser


def _detector(model_path: str, threshold: float) -> HybridDetector:
    return HybridDetector(LinearModel.load(model_path), threshold=threshold)


def _print_result(result) -> None:
    icon = "ALERT" if result.is_alert else "OK"
    reason = "；".join(result.reasons)
    print(
        f"[{icon:5}] risk={result.risk_score:.4f} severity={result.severity:8} "
        f"{result.src_ip} -> {result.dst_ip}:{result.dst_port}/{result.protocol} | {reason}"
    )


def run_demo(args: argparse.Namespace) -> int:
    detector = _detector(args.model, args.threshold)
    results = [detector.analyze(flow) for flow in read_flows(DEFAULT_SAMPLE)]
    for result in results:
        _print_result(result)
    print(f"\n共分析 {len(results)} 条，产生 {sum(r.is_alert for r in results)} 条告警。")
    return 0


def run_analyze(args: argparse.Namespace) -> int:
    detector = _detector(args.model, args.threshold)
    results = [detector.analyze(flow) for flow in read_flows(args.input)]
    selected = results if args.all else [result for result in results if result.is_alert]
    write_jsonl(selected, args.output)
    for result in results:
        _print_result(result)
    print(f"\n已将 {len(selected)} 条结果写入 {args.output}")
    return 0


def run_train(args: argparse.Namespace) -> int:
    flows = read_flows(args.input)
    model = train_logistic_model(flows, epochs=args.epochs, learning_rate=args.learning_rate)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    save_model(model, output)
    print(json.dumps(model["metadata"], ensure_ascii=False, indent=2))
    print(f"模型已保存到 {output}")
    return 0


def run_evaluate(args: argparse.Namespace) -> int:
    flows = read_flows(args.input)
    detector = _detector(args.model, args.threshold)
    tp = fp = tn = fn = 0
    for flow in flows:
        actual = label_to_int(flow.label)
        predicted = int(detector.analyze(flow).is_alert)
        tp += predicted == 1 and actual == 1
        fp += predicted == 1 and actual == 0
        tn += predicted == 0 and actual == 0
        fn += predicted == 0 and actual == 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    report = {
        "rows": len(flows), "true_positive": tp, "false_positive": fp,
        "true_negative": tn, "false_negative": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows terminals may inherit a legacy encoding. Keep Chinese explanations
    # readable and prevent one unsupported character from aborting analysis.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    actions = {
        "demo": run_demo,
        "analyze": run_analyze,
        "train": run_train,
        "evaluate": run_evaluate,
    }
    try:
        return actions[args.command](args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"错误: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
