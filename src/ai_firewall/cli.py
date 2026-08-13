from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .detector import HybridDetector
from .io import read_flows, write_flows_csv, write_jsonl
from .model import LinearModel
from .pcap import read_capture
from .training import label_to_int, save_model, train_logistic_model
from .windows_monitor import WindowsFlowTracker, collect_connections
from .windows_capture import capture_with_pktmon
from .benchmark import build_benchmark_report, write_benchmark_report


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

    pcap = sub.add_parser("pcap", help="将 classic PCAP 或 PCAPNG 转换为网络流 CSV")
    pcap.add_argument("input")
    pcap.add_argument("--output", default="flows.csv")
    pcap.add_argument("--max-packets", type=int)
    pcap.add_argument("--analyze", action="store_true", help="转换后立即运行检测")
    pcap.add_argument("--alerts", default="pcap-alerts.jsonl")
    pcap.add_argument("--model", default=str(DEFAULT_MODEL))
    pcap.add_argument("--threshold", type=float, default=0.60)
    pcap.add_argument("--directional", action="store_true", help="不合并反向数据包")

    monitor = sub.add_parser("monitor", help="实时监控 Windows TCP 连接")
    monitor.add_argument("--interval", type=float, default=2.0)
    monitor.add_argument("--duration", type=float, default=60.0, help="秒；0 表示持续运行")
    monitor.add_argument("--once", action="store_true", help="只采集一次当前连接")
    monitor.add_argument("--output", default="live-alerts.jsonl")
    monitor.add_argument("--all", action="store_true", help="写入全部新连接，而不仅是告警")
    monitor.add_argument("--model", default=str(DEFAULT_MODEL))
    monitor.add_argument("--threshold", type=float, default=0.60)

    capture = sub.add_parser("capture", help="使用 Windows pktmon 进行限时包级采集")
    capture.add_argument("--duration", type=float, default=30.0)
    capture.add_argument("--output", default="capture.pcapng")
    capture.add_argument("--overwrite", action="store_true")
    capture.add_argument("--analyze", action="store_true", help="采集完成后立即检测")
    capture.add_argument("--flows", default="captured-flows.csv")
    capture.add_argument("--alerts", default="capture-alerts.jsonl")
    capture.add_argument("--model", default=str(DEFAULT_MODEL))
    capture.add_argument("--threshold", type=float, default=0.60)

    benchmark = sub.add_parser("benchmark", help="按时间切分并建立独立误报基线")
    benchmark.add_argument("input", help="带标签和 ISO 8601 时间戳的 CSV")
    benchmark.add_argument("--model", default=str(DEFAULT_MODEL))
    benchmark.add_argument("--calibration-fraction", type=float, default=0.4)
    benchmark.add_argument("--target-fpr", type=float, default=0.01)
    benchmark.add_argument("--output", default="benchmark-report.json")
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


def run_pcap(args: argparse.Namespace) -> int:
    flows = read_capture(
        args.input, max_packets=args.max_packets, bidirectional=not args.directional,
    )
    write_flows_csv(flows, args.output)
    print(f"已从 PCAP 聚合 {len(flows)} 条网络流，写入 {args.output}")
    if args.analyze:
        detector = _detector(args.model, args.threshold)
        results = [detector.analyze(flow) for flow in flows]
        alerts = [result for result in results if result.is_alert]
        write_jsonl(alerts, args.alerts)
        for result in results:
            _print_result(result)
        print(f"产生 {len(alerts)} 条告警，写入 {args.alerts}")
    return 0


def run_capture(args: argparse.Namespace) -> int:
    print(f"将在本机采集 {args.duration:g} 秒，输出到 {args.output}；不会上传数据。")
    capture_path = capture_with_pktmon(args.duration, args.output, overwrite=args.overwrite)
    print(f"包级采集完成: {capture_path}")
    if args.analyze:
        flows = read_capture(capture_path)
        write_flows_csv(flows, args.flows)
        detector = _detector(args.model, args.threshold)
        results = [detector.analyze(flow) for flow in flows]
        alerts = [result for result in results if result.is_alert]
        write_jsonl(alerts, args.alerts)
        print(f"聚合 {len(flows)} 条双向流，产生 {len(alerts)} 条告警。")
    return 0


def run_benchmark(args: argparse.Namespace) -> int:
    flows = read_flows(args.input)
    model = LinearModel.load(args.model)
    report = build_benchmark_report(
        model,
        flows,
        calibration_fraction=args.calibration_fraction,
        target_fpr=args.target_fpr,
        source=str(Path(args.input)),
    )
    write_benchmark_report(report, args.output)
    summary = {
        "threshold": report["calibration"]["threshold"],
        "test_rows": report["independent_test"]["rows"],
        "precision": report["independent_test"]["precision"],
        "recall": report["independent_test"]["recall"],
        "false_positive_rate": report["independent_test"]["false_positive_rate"],
        "false_positives_per_day": report["independent_test"]["false_positives_per_day"],
        "warnings": report["warnings"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"完整基线报告已写入 {args.output}")
    return 0


def run_monitor(args: argparse.Namespace) -> int:
    if args.interval <= 0 or args.duration < 0:
        raise ValueError("interval 必须大于 0，duration 不能小于 0")
    detector = _detector(args.model, args.threshold)
    tracker = WindowsFlowTracker()
    started = time.monotonic()
    written = observed = 0
    print("Windows 实时监控已启动；按 Ctrl+C 停止。")
    with Path(args.output).open("w", encoding="utf-8") as handle:
        try:
            while True:
                observations = tracker.observe(collect_connections(), time.time())
                for observation in observations:
                    observed += 1
                    result = detector.analyze(observation.flow)
                    process = f"{observation.process_name}({observation.process_id})"
                    print(f"[{observation.direction:8}] process={process:24} state={observation.state:12}", end=" ")
                    _print_result(result)
                    if args.all or result.is_alert:
                        payload = result.to_dict() | {
                            "process_id": observation.process_id,
                            "process_name": observation.process_name,
                            "connection_state": observation.state,
                            "direction": observation.direction,
                        }
                        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
                        handle.flush()
                        written += 1
                if args.once or (args.duration and time.monotonic() - started >= args.duration):
                    break
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n已停止监控。")
    print(f"共观察 {observed} 条新连接，写入 {written} 条记录到 {args.output}")
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
        "pcap": run_pcap,
        "monitor": run_monitor,
        "capture": run_capture,
        "benchmark": run_benchmark,
    }
    try:
        return actions[args.command](args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"错误: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
