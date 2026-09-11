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
from .datasets import iter_dataset
from .comparison import build_model_comparison, write_comparison_report
from .research import (
    DEFAULT_RESEARCH_SEEDS,
    DEFAULT_TARGET_FPRS,
    aggregate_research_reports,
    build_research_report,
    grid_search_lightgbm,
    write_lightgbm_grid_search_bundle,
    write_multiseed_bundle,
    write_research_bundle,
)
from .dashboard import serve_dashboard
from .feedback import build_feedback_model, review_feedback
from .firewall import (
    activate_kill_switch, apply_temporary_block, cleanup_expired_rules,
    deactivate_kill_switch, plan_temporary_block, rollback_rules,
)
from .updates import (
    create_signed_bundle, generate_signing_keys, install_signed_bundle, rollback_model,
)
from .performance import build_performance_report, write_performance_report
from .baseline_gate import evaluate_baseline_gate, write_gate_report
from .lab import (
    LAB_CONFIRMATION, SCENARIOS, run_loopback_lab, validate_lab_report_output,
    write_lab_report,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL = PROJECT_ROOT / "models" / "baseline.json"
DEFAULT_SAMPLE = PROJECT_ROOT / "data" / "sample_flows.csv"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-firewall",
        description="用于网络流检测、模型训练和评估的命令行工具。",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="分析仓库附带的演示数据")
    demo.add_argument("--model", default=str(DEFAULT_MODEL))
    demo.add_argument("--threshold", type=float, default=0.60)

    lab = sub.add_parser("lab-simulate", help="在 127.0.0.1 上运行受控 Socket 测试")
    lab.add_argument("--scenario", choices=("all", *SCENARIOS), default="all")
    lab.add_argument("--model", default=str(DEFAULT_MODEL))
    lab.add_argument("--threshold", type=float, default=0.60)
    lab.add_argument("--output", default="lab-report.json")
    lab.add_argument("--overwrite", action="store_true")
    lab.add_argument(
        "--confirm", default="",
        help=f"实际产生 loopback 流量前必须为 {LAB_CONFIRMATION}",
    )

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

    dataset = sub.add_parser("convert-dataset", help="将公开 IDS 数据集转换为统一网络流 CSV")
    dataset.add_argument("format", choices=("cicids2017", "unsw-nb15"))
    dataset.add_argument("input")
    dataset.add_argument("--output", default="converted-flows.csv")
    dataset.add_argument("--timestamp-format", help="CICIDS2017 日期格式，例如 %%d/%%m/%%Y %%H:%%M")
    dataset.add_argument("--max-rows", type=int, help="只转换前 N 行，用于安全试跑")
    dataset.add_argument("--overwrite", action="store_true", help="允许替换已存在的输出文件")

    compare = sub.add_parser("compare-models", help="用同一时间切分对比三种检测模型")
    compare.add_argument("input", help="至少 20 条、带标签和 ISO 8601 时间戳的 CSV")
    compare.add_argument("--train-fraction", type=float, default=0.5)
    compare.add_argument("--calibration-fraction", type=float, default=0.2)
    compare.add_argument("--target-fpr", type=float, default=0.01)
    compare.add_argument("--seed", type=int, default=42)
    compare.add_argument("--output", default="model-comparison.json")
    compare.add_argument("--overwrite", action="store_true")

    research = sub.add_parser(
        "research-experiment",
        help="运行论文用的时间切分、固定误报率和五种检测配置对比",
    )
    research.add_argument("input", help="至少 20 条、带标签和 ISO 8601 时间戳的统一 CSV")
    research.add_argument("--train-fraction", type=float, default=0.5)
    research.add_argument("--calibration-fraction", type=float, default=0.2)
    research.add_argument(
        "--target-fpr", type=float, action="append",
        help="可重复指定；默认运行 0.005、0.01 和 0.02",
    )
    research.add_argument("--seed", type=int, default=42)
    research.add_argument("--batch-size", type=int, default=256)
    research.add_argument(
        "--logistic-epochs", type=int, default=50,
        help="内置逻辑回归训练轮数；大型论文数据默认 50",
    )
    research.add_argument("--with-shap", action="store_true")
    research.add_argument("--shap-background-size", type=int, default=100)
    research.add_argument("--shap-summary-size", type=int, default=2000)
    research.add_argument(
        "--lightgbm-grid-search", action="store_true",
        help="仅在外层训练时段内执行 36 组嵌套时间顺序网格搜索",
    )
    research.add_argument("--output-dir", default="research-results")
    research.add_argument("--overwrite", action="store_true")

    multiseed = sub.add_parser(
        "research-multiseed",
        help="用固定时间切分运行多随机种子，并自动汇总均值和样本标准差",
    )
    multiseed.add_argument("input", help="至少 20 条、带标签和 ISO 8601 时间戳的统一 CSV")
    multiseed.add_argument("--train-fraction", type=float, default=0.5)
    multiseed.add_argument("--calibration-fraction", type=float, default=0.2)
    multiseed.add_argument(
        "--target-fpr", type=float, action="append",
        help="可重复指定；默认运行 0.005、0.01 和 0.02",
    )
    multiseed.add_argument(
        "--seed", type=int, action="append",
        help="可重复指定；默认使用 11、23、42、67 和 89",
    )
    multiseed.add_argument("--batch-size", type=int, default=256)
    multiseed.add_argument("--logistic-epochs", type=int, default=50)
    multiseed.add_argument("--with-shap", action="store_true")
    multiseed.add_argument(
        "--shap-seed", type=int, default=42,
        help="只在这个代表种子上计算 LightGBM SHAP；默认 42",
    )
    multiseed.add_argument("--shap-background-size", type=int, default=100)
    multiseed.add_argument("--shap-summary-size", type=int, default=2000)
    multiseed.add_argument(
        "--lightgbm-grid-search", action="store_true",
        help="每个数据集只搜索一次，再将胜出参数固定用于全部 seed",
    )
    multiseed.add_argument("--output-dir", default="research-multiseed-results")
    multiseed.add_argument("--overwrite", action="store_true")

    dashboard = sub.add_parser("dashboard", help="启动仅监听本机地址的连接与告警页面")
    dashboard.add_argument("--input", default="alerts.jsonl", help="analyze/monitor 生成的 JSONL")
    dashboard.add_argument("--feedback", default="feedback/pending.jsonl", help="独立误报审核队列")
    dashboard.add_argument("--port", type=int, default=8765)
    dashboard.add_argument("--max-alerts", type=int, default=500)

    review = sub.add_parser("review-feedback", help="人工批准或拒绝隔离队列中的反馈")
    review.add_argument("--alerts", required=True, help="生成反馈时对应的告警 JSONL")
    review.add_argument("--pending", default="feedback/pending.jsonl")
    review.add_argument("--reviewed", default="feedback/reviewed.jsonl")
    review.add_argument("--decision", required=True, choices=("approve", "reject"))
    selection = review.add_mutually_exclusive_group(required=True)
    selection.add_argument("--alert-id", action="append", help="可重复指定短指纹")
    selection.add_argument("--all", action="store_true", help="审核队列中的全部待办")
    review.add_argument("--reviewer", default="local-user")

    retrain = sub.add_parser("retrain-feedback", help="用授权基线数据和已批准反馈重新训练")
    retrain.add_argument("base_csv", help="已授权、带标签的基础训练 CSV")
    retrain.add_argument("--reviewed", default="feedback/reviewed.jsonl")
    retrain.add_argument("--output", default="models/feedback-model.json")
    retrain.add_argument("--epochs", type=int, default=800)
    retrain.add_argument("--learning-rate", type=float, default=0.08)
    retrain.add_argument("--max-feedback-fraction", type=float, default=0.20)
    retrain.add_argument("--overwrite", action="store_true")

    fw_block = sub.add_parser("firewall-block", help="规划或显式执行 Windows 临时封禁")
    fw_block.add_argument("address")
    fw_block.add_argument("--duration", type=int, default=600, help="60..86400 秒")
    fw_block.add_argument("--allowlist")
    fw_block.add_argument("--state", default="state/firewall-rules.json")
    fw_block.add_argument("--apply", action="store_true", help="实际修改 Windows 防火墙")
    fw_block.add_argument("--confirm", default="", help="实际执行必须为 APPLY")

    fw_rollback = sub.add_parser("firewall-rollback", help="回滚 AI Firewall 托管规则")
    fw_rollback.add_argument("--state", default="state/firewall-rules.json")
    fw_rollback.add_argument("--apply", action="store_true")
    fw_rollback.add_argument("--confirm", default="", help="实际执行必须为 ROLLBACK")

    fw_cleanup = sub.add_parser("firewall-cleanup", help="删除已到期的托管临时封禁规则")
    fw_cleanup.add_argument("--state", default="state/firewall-rules.json")
    fw_cleanup.add_argument("--apply", action="store_true")
    fw_cleanup.add_argument("--confirm", default="", help="实际执行必须为 CLEANUP")

    kill = sub.add_parser("firewall-kill-switch", help="禁止新增规则，可选择回滚全部托管规则")
    kill.add_argument("--state", default="state/firewall-rules.json")
    kill.add_argument("--rollback", action="store_true")
    kill.add_argument("--confirm", default="", help="回滚时必须为 ROLLBACK")

    enable_fw = sub.add_parser("firewall-enable", help="关闭 kill switch，重新允许显式封禁")
    enable_fw.add_argument("--state", default="state/firewall-rules.json")
    enable_fw.add_argument("--confirm", default="", help="必须为 ENABLE")

    keys = sub.add_parser("generate-signing-key", help="生成本地 Ed25519 模型签名密钥")
    keys.add_argument("--private-key", required=True)
    keys.add_argument("--public-key", required=True)
    keys.add_argument("--overwrite", action="store_true")

    sign = sub.add_parser("sign-model", help="创建经 Ed25519 签名的 .aifw 更新包")
    sign.add_argument("model")
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--version", required=True)
    sign.add_argument("--min-app-version", default="1.0.0")
    sign.add_argument("--output", required=True)
    sign.add_argument("--overwrite", action="store_true")

    install = sub.add_parser("install-model-update", help="验证签名和固定版本后原子更新模型")
    install.add_argument("bundle")
    install.add_argument("--public-key", required=True)
    install.add_argument("--expected-version", required=True)
    install.add_argument("--target", required=True)

    model_rollback = sub.add_parser("rollback-model", help="恢复上一次已验证模型")
    model_rollback.add_argument("--target", required=True)

    perf = sub.add_parser("performance-test", help="生成可复现的 CPU/内存/延迟报告")
    perf.add_argument("input")
    perf.add_argument("--model", default=str(DEFAULT_MODEL))
    perf.add_argument("--threshold", type=float, default=0.60)
    perf.add_argument("--iterations", type=int, default=100)
    perf.add_argument("--warmup", type=int, default=10)
    perf.add_argument("--max-p95-ms", type=float, default=5.0)
    perf.add_argument("--max-peak-mib", type=float, default=128.0)
    perf.add_argument("--output", default="performance-report.json")
    perf.add_argument("--overwrite", action="store_true")

    gate = sub.add_parser("baseline-gate", help="检查真实环境误报基线是否达到发布门槛")
    gate.add_argument("benchmark_report")
    gate.add_argument("provenance", help="授权、脱敏和独立留出声明 JSON")
    gate.add_argument("--min-days", type=int, default=3)
    gate.add_argument("--min-benign-rows", type=int, default=1000)
    gate.add_argument("--max-fpr", type=float, default=0.01)
    gate.add_argument("--max-false-positives-per-day", type=float, default=10.0)
    gate.add_argument("--min-recall", type=float, default=0.80)
    gate.add_argument("--output", default="baseline-gate-report.json")
    gate.add_argument("--overwrite", action="store_true")
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
    if result.is_alert:
        features = ", ".join(
            f"{item['name']}={item['value']:g} "
            f"({item['direction']} {abs(item['contribution']):.4f})"
            for item in result.top_features
        )
        rules = ", ".join(
            f"{item['rule_id']}({item['score']:.2f})"
            for item in result.rule_evidence
        ) or "none"
        print(
            f"        model={result.model_algorithm}@{result.model_version} | "
            f"top_features={features} | rules={rules}"
        )


def run_demo(args: argparse.Namespace) -> int:
    detector = _detector(args.model, args.threshold)
    results = [detector.analyze(flow) for flow in read_flows(DEFAULT_SAMPLE)]
    for result in results:
        _print_result(result)
    print(f"\n共分析 {len(results)} 条，产生 {sum(r.is_alert for r in results)} 条告警。")
    return 0


def run_lab_simulate(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.resolve() == Path(args.model).resolve():
        raise ValueError("本机实验报告不能覆盖检测模型")
    validate_lab_report_output(output, overwrite=args.overwrite)
    print(
        "本机实验只会连接 127.0.0.1 上由程序自己占用的端口；"
        "不会抓包、使用真实账户、修改防火墙或访问外部网络。"
    )
    report = run_loopback_lab(
        _detector(args.model, args.threshold),
        scenario=args.scenario,
        confirmation=args.confirm,
    )
    write_lab_report(report, output, overwrite=args.overwrite)
    for item in report["scenarios"]:
        status = str(item["status"]).upper()
        print(f"[{status:6}] {item['scenario']}")
        detection = item.get("detection")
        if isinstance(detection, dict):
            print(
                f"         risk={detection['risk_score']:.4f} "
                f"severity={detection['severity']} rules={detection['rule_ids']}"
            )
        elif item.get("error"):
            print(f"         {item['error']}")
    print(f"本机实验整体结果: {'PASS' if report['passed'] else 'FAIL'}；报告已写入 {args.output}")
    print("该结果不能替代跨日真实正常流量误报基线，也不验证 pktmon 抓包链路。")
    return 0 if report["passed"] else 1


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


def run_convert_dataset(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()
    if input_path == output_path:
        raise ValueError("输出文件不能与输入数据集相同")
    if output_path.exists() and not args.overwrite:
        raise ValueError(f"输出文件已存在: {output_path}；如需替换请添加 --overwrite")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + ".tmp")
    if temporary.exists():
        raise ValueError(f"临时输出已存在，请先检查或移走: {temporary}")
    try:
        flows = iter_dataset(
            args.format, input_path,
            timestamp_format=args.timestamp_format,
            max_rows=args.max_rows,
        )
        count = write_flows_csv(flows, temporary)
        if output_path.exists() and not args.overwrite:
            raise ValueError(f"输出文件已存在: {output_path}；转换结果未覆盖它")
        temporary.replace(output_path)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"已将 {args.format} 的 {count} 条记录转换到 {output_path}")
    print("转换仅处理 CSV 元数据；未下载数据、未读取 PCAP、未发送任何网络流量。")
    return 0


def run_compare_models(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    output = Path(args.output)
    if output.resolve() == input_path:
        raise ValueError("模型对比输出不能与输入 CSV 相同")
    if output.exists() and not args.overwrite:
        raise ValueError(f"输出文件已存在: {output}；如需替换请添加 --overwrite")
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists():
        raise ValueError(f"临时输出已存在，请先检查或移走: {temporary}")
    flows = read_flows(input_path)
    report = build_model_comparison(
        flows,
        train_fraction=args.train_fraction,
        calibration_fraction=args.calibration_fraction,
        target_fpr=args.target_fpr,
        seed=args.seed,
        source=str(input_path),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        write_comparison_report(report, temporary)
        if output.exists() and not args.overwrite:
            raise ValueError(f"输出文件已存在: {output}；对比结果未覆盖它")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    summary = {
        name: result["independent_test"] for name, result in report["models"].items()
    }
    print(json.dumps({"ranking": report["ranking"], "models": summary}, ensure_ascii=False, indent=2))
    print(f"完整模型对比报告已写入 {output}")
    return 0


def run_research_experiment(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    output_dir = Path(args.output_dir).resolve()
    if output_dir == input_path or input_path in output_dir.parents:
        raise ValueError("论文实验输出目录不能覆盖输入 CSV")
    flows = read_flows(input_path)
    lightgbm_tuning = None
    if args.lightgbm_grid_search:
        print("在外层训练时段内执行 LightGBM 嵌套时间顺序网格搜索 ...")
        lightgbm_tuning = grid_search_lightgbm(
            flows,
            train_fraction=args.train_fraction,
            calibration_fraction=args.calibration_fraction,
            target_fpr=0.01,
            seed=42,
            source=str(input_path),
        )
    report = build_research_report(
        flows,
        train_fraction=args.train_fraction,
        calibration_fraction=args.calibration_fraction,
        target_fprs=args.target_fpr or DEFAULT_TARGET_FPRS,
        seed=args.seed,
        source=str(input_path),
        batch_size=args.batch_size,
        logistic_epochs=args.logistic_epochs,
        include_shap=args.with_shap,
        shap_background_size=args.shap_background_size,
        shap_summary_size=args.shap_summary_size,
        lightgbm_tuning=lightgbm_tuning,
    )
    outputs = write_research_bundle(report, output_dir, overwrite=args.overwrite)
    if lightgbm_tuning:
        outputs.extend(write_lightgbm_grid_search_bundle(
            lightgbm_tuning, output_dir, overwrite=args.overwrite,
        ))
    primary = f"{float(report['primary_target_false_positive_rate']):g}"
    summary = {
        name: result["operating_points"][primary]["independent_test"]
        for name, result in report["configurations"].items()
    }
    print(json.dumps({
        "primary_target_fpr": report["primary_target_false_positive_rate"],
        "ranking": report["ranking_at_primary_target"],
        "configurations": summary,
    }, ensure_ascii=False, indent=2))
    print("论文实验文件已写入：")
    for output in outputs:
        print(f"- {output}")
    return 0


def run_research_multiseed(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    output_dir = Path(args.output_dir).resolve()
    if output_dir == input_path or input_path in output_dir.parents:
        raise ValueError("论文实验输出目录不能覆盖输入 CSV")
    seeds = tuple(sorted(set(args.seed or DEFAULT_RESEARCH_SEEDS)))
    if len(seeds) < 2:
        raise ValueError("多随机种子实验至少需要两个不同 seed")
    if args.with_shap and args.shap_seed not in seeds:
        raise ValueError("--shap-seed 必须同时出现在 --seed 列表中")
    flows = read_flows(input_path)
    lightgbm_tuning = None
    if args.lightgbm_grid_search:
        print("先在外层训练时段内执行一次 LightGBM 嵌套时间顺序网格搜索 ...")
        lightgbm_tuning = grid_search_lightgbm(
            flows,
            train_fraction=args.train_fraction,
            calibration_fraction=args.calibration_fraction,
            target_fpr=0.01,
            seed=42,
            source=str(input_path),
        )
        print(json.dumps({
            "selected_lightgbm_params": lightgbm_tuning["best_params"],
            "selection_constraint_met": lightgbm_tuning[
                "selection_constraint_met"
            ],
        }, ensure_ascii=False, indent=2))
    reports = []
    for seed in seeds:
        print(f"运行 seed={seed}{' + SHAP' if args.with_shap and seed == args.shap_seed else ''} ...")
        report = build_research_report(
            flows,
            train_fraction=args.train_fraction,
            calibration_fraction=args.calibration_fraction,
            target_fprs=args.target_fpr or DEFAULT_TARGET_FPRS,
            seed=seed,
            source=str(input_path),
            batch_size=args.batch_size,
            logistic_epochs=args.logistic_epochs,
            include_shap=args.with_shap and seed == args.shap_seed,
            shap_background_size=args.shap_background_size,
            shap_summary_size=args.shap_summary_size,
            lightgbm_tuning=lightgbm_tuning,
        )
        write_research_bundle(
            report, output_dir / f"seed-{seed}", overwrite=args.overwrite,
        )
        reports.append(report)
    aggregate = aggregate_research_reports(reports)
    outputs = write_multiseed_bundle(aggregate, output_dir, overwrite=args.overwrite)
    print(json.dumps({
        "seeds": aggregate["seeds"],
        "source": aggregate["source"],
        "primary_target_fpr": aggregate["primary_target_false_positive_rate"],
    }, ensure_ascii=False, indent=2))
    print("多随机种子汇总文件已写入：")
    for output in outputs:
        print(f"- {output}")
    return 0


def run_dashboard(args: argparse.Namespace) -> int:
    serve_dashboard(
        args.input, args.feedback, port=args.port, max_alerts=args.max_alerts,
    )
    return 0


def run_review_feedback(args: argparse.Namespace) -> int:
    report = review_feedback(
        args.alerts, args.pending, args.reviewed,
        decision=args.decision,
        alert_ids=None if args.all else set(args.alert_id or []),
        reviewer=args.reviewer,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("审核决定已写入独立账本；当前模型没有自动变化。")
    return 0


def _replace_output(output: Path, model: dict[str, object], overwrite: bool) -> None:
    if output.exists() and not overwrite:
        raise ValueError(f"输出文件已存在: {output}；如需替换请添加 --overwrite")
    if output.is_symlink():
        raise ValueError("输出文件不能是符号链接")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("临时输出已存在，请先人工检查")
    try:
        save_model(model, temporary)
        LinearModel.load(temporary)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def run_retrain_feedback(args: argparse.Namespace) -> int:
    model = build_feedback_model(
        args.base_csv, args.reviewed,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        max_feedback_fraction=args.max_feedback_fraction,
    )
    output = Path(args.output)
    _replace_output(output, model, args.overwrite)
    print(json.dumps(model["metadata"], ensure_ascii=False, indent=2))
    print(f"经人工批准的反馈模型已保存到 {output}；不会自动启用或修改防火墙。")
    return 0


def run_firewall_block(args: argparse.Namespace) -> int:
    if not args.apply:
        plan = plan_temporary_block(
            args.address, args.duration, allowlist_path=args.allowlist,
        )
        print(json.dumps({"dry_run": True, "rule": plan}, ensure_ascii=False, indent=2))
        print("仅生成计划；没有修改 Windows 防火墙。实际执行还需 --apply --confirm APPLY。")
        return 0
    result = apply_temporary_block(
        args.address, args.duration, args.state,
        allowlist_path=args.allowlist, confirmation=args.confirm,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def run_firewall_rollback(args: argparse.Namespace) -> int:
    if not args.apply:
        print("dry-run：没有修改 Windows 防火墙。实际回滚需 --apply --confirm ROLLBACK。")
        return 0
    print(json.dumps(
        rollback_rules(args.state, confirmation=args.confirm), ensure_ascii=False, indent=2,
    ))
    return 0


def run_firewall_cleanup(args: argparse.Namespace) -> int:
    if not args.apply:
        print("dry-run：没有修改 Windows 防火墙。实际清理需 --apply --confirm CLEANUP。")
        return 0
    print(json.dumps(
        cleanup_expired_rules(args.state, confirmation=args.confirm),
        ensure_ascii=False, indent=2,
    ))
    return 0


def run_firewall_kill_switch(args: argparse.Namespace) -> int:
    print(json.dumps(
        activate_kill_switch(
            args.state, rollback=args.rollback, confirmation=args.confirm,
        ),
        ensure_ascii=False, indent=2,
    ))
    print("kill switch 已启用：后续实际封禁会被拒绝。")
    return 0


def run_firewall_enable(args: argparse.Namespace) -> int:
    changed = deactivate_kill_switch(args.state, confirmation=args.confirm)
    print("kill switch 已关闭。" if changed else "kill switch 原本未启用。")
    return 0


def run_generate_signing_key(args: argparse.Namespace) -> int:
    generate_signing_keys(
        args.private_key, args.public_key, overwrite=args.overwrite,
    )
    print(f"私钥已保存到 {args.private_key}（不得提交）；公钥已保存到 {args.public_key}。")
    return 0


def run_sign_model(args: argparse.Namespace) -> int:
    manifest = create_signed_bundle(
        args.model, args.private_key, args.output,
        version=args.version,
        min_app_version=args.min_app_version,
        overwrite=args.overwrite,
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


def run_install_model_update(args: argparse.Namespace) -> int:
    print(json.dumps(
        install_signed_bundle(
            args.bundle, args.public_key, args.target,
            expected_version=args.expected_version,
        ),
        ensure_ascii=False, indent=2,
    ))
    return 0


def run_rollback_model(args: argparse.Namespace) -> int:
    print(json.dumps(rollback_model(args.target), ensure_ascii=False, indent=2))
    return 0


def run_performance_test(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.exists() and not args.overwrite:
        raise ValueError(f"输出文件已存在: {output}；如需替换请添加 --overwrite")
    if output.is_symlink():
        raise ValueError("性能报告输出不能是符号链接")
    report = build_performance_report(
        _detector(args.model, args.threshold), read_flows(args.input),
        iterations=args.iterations, warmup=args.warmup,
        max_p95_ms=args.max_p95_ms, max_peak_mib=args.max_peak_mib,
    )
    write_performance_report(report, output)
    print(json.dumps(report["metrics"], ensure_ascii=False, indent=2))
    print(f"性能门槛: {'PASS' if report['passed'] else 'FAIL'}；完整报告已写入 {output}")
    return 0 if report["passed"] else 1


def run_baseline_gate(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.exists() and not args.overwrite:
        raise ValueError(f"输出文件已存在: {output}；如需替换请添加 --overwrite")
    if output.is_symlink():
        raise ValueError("基线验收报告输出不能是符号链接")
    report = evaluate_baseline_gate(
        args.benchmark_report, args.provenance,
        min_days=args.min_days,
        min_benign_rows=args.min_benign_rows,
        max_fpr=args.max_fpr,
        max_false_positives_per_day=args.max_false_positives_per_day,
        min_recall=args.min_recall,
    )
    write_gate_report(report, output)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "passed" else 1


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
    # Force UTF-8 output because some Windows terminals still default to a legacy
    # code page and may otherwise fail while printing Chinese messages.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    actions = {
        "demo": run_demo,
        "lab-simulate": run_lab_simulate,
        "analyze": run_analyze,
        "train": run_train,
        "evaluate": run_evaluate,
        "pcap": run_pcap,
        "monitor": run_monitor,
        "capture": run_capture,
        "benchmark": run_benchmark,
        "convert-dataset": run_convert_dataset,
        "compare-models": run_compare_models,
        "research-experiment": run_research_experiment,
        "research-multiseed": run_research_multiseed,
        "dashboard": run_dashboard,
        "review-feedback": run_review_feedback,
        "retrain-feedback": run_retrain_feedback,
        "firewall-block": run_firewall_block,
        "firewall-rollback": run_firewall_rollback,
        "firewall-cleanup": run_firewall_cleanup,
        "firewall-kill-switch": run_firewall_kill_switch,
        "firewall-enable": run_firewall_enable,
        "generate-signing-key": run_generate_signing_key,
        "sign-model": run_sign_model,
        "install-model-update": run_install_model_update,
        "rollback-model": run_rollback_model,
        "performance-test": run_performance_test,
        "baseline-gate": run_baseline_gate,
    }
    try:
        return actions[args.command](args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"错误: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
