# AI Firewall（AI 防火墙）

[![tests](https://github.com/heartofiron-dev/ai-firewall/actions/workflows/tests.yml/badge.svg)](https://github.com/heartofiron-dev/ai-firewall/actions/workflows/tests.yml)

这是我做的一个本地网络安全项目。

我最开始的想法其实很直接：Windows 会产生大量网络连接，但普通用户很难看懂“哪个连接只是正常联网，哪个连接可能值得警惕”。传统安全工具往往只给一个结论，我想做一个能够把判断过程说清楚的检测器——它为什么报警、命中了什么规则、哪些特征推高了风险，都应该能查到。

所以我把项目叫作 **AI Firewall**。定位是一个 **Explainable AI Network Monitor（可解释 AI 网络监控器）**，不是可以代替 Windows Defender、Zeek、Suricata 或企业 SIEM 的生产级防火墙。

当前版本：`1.2.0`

## 它现在能做什么

- 分析 CSV 网络流记录，并输出 JSONL 告警；
- 读取 classic PCAP 和 PCAPNG，把包聚合成双向网络流；
- 在 Windows 上查看实时 TCP 连接、进程、PID、方向和状态；
- 使用 Windows 自带的 `pktmon` 做有时限的本地抓包；
- 用可解释规则和轻量逻辑回归模型共同计算风险；
- 显示每条告警命中的规则、模型版本和主要特征贡献；
- 启动一个只绑定 `127.0.0.1` 的本地仪表盘；
- 训练、评估和比较逻辑回归、Isolation Forest、LightGBM；
- 把误报放进隔离队列，人工审核后再决定是否参与训练；
- 生成 Windows 防火墙临时规则计划，并在多重确认后执行或回滚；
- 验证 Ed25519 签名的模型更新包，并保留回滚版本；
- 在 `127.0.0.1` 上运行六种有上限的安全 Socket 实验。

默认情况下，项目只做观察和告警。它不会偷偷上传网络记录，不会自动训练，也不会因为一次模型判断就自动封禁地址。

## 最快的体验方式

要求 Python 3.10 或更高版本。核心功能没有第三方运行依赖。

```powershell
git clone https://github.com/heartofiron-dev/ai-firewall.git
cd ai-firewall
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
ai-firewall demo
```

`demo` 只读取仓库里的安全样本，不会抓包、扫描网络或修改电脑设置。正常情况下会看到 6 条结果：2 条 `OK`，4 条 `ALERT`。

如果 PowerShell 不允许激活虚拟环境，也可以直接这样运行：

```powershell
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\python.exe -m ai_firewall.cli demo
```

## 我是怎么计算风险的

项目会从每条网络流中提取 10 个数值特征，包括连接时长、包数量、总字节数、平均包大小、SYN/RST 比例、60 秒连接数、60 秒失败次数、60 秒目标端口数和高风险端口标记。

逻辑回归先计算：

```text
z = b + w1*x1 + w2*x2 + ... + wn*xn
p = 1 / (1 + e^(-z))
```

`p` 是模型风险分数。规则系统会另外给出 `rule_score`，最后组合为：

```text
risk = max(0.70 * model_score + 0.30 * rule_score,
           0.90 * rule_score)
```

第二项是规则保底：如果一条强规则已经命中，不会因为模型没见过这种情况就把它完全压下去。

这里所谓的“AI”不是一个不可解释的大模型，而是一个小型统计模型。每条告警都会保留贡献最大的特征和具体规则证据。我更看重“为什么得出这个结果”，而不只是输出一个看起来很聪明的分数。

## 当前能识别的五类行为

| 行为 | 判断信号 | 规则 ID |
|---|---|---|
| 端口扫描 | 60 秒内访问大量不同端口 | `PORT_SCAN` |
| 认证爆破 | SSH、RDP 等端口连续连接失败 | `BRUTE_FORCE` |
| 连接洪泛 | 短时间连接或 SYN 数量异常 | `CONNECTION_FLOOD` |
| 数据突增 | 短时间传输的数据量异常增大 | `DATA_SPIKE` |
| 可疑端口通信 | 连接到常见恶意工具或后门端口 | `SUSPICIOUS_PORT` |

模型还可以发现没有命中上述规则、但统计特征偏离基线的流量。不过“异常”不等于“攻击”，告警仍然需要结合进程、目的地和实际使用场景复核。

## 几种常用方式

### 1. 分析 CSV

```powershell
ai-firewall analyze data/sample_flows.csv --output alerts.jsonl
```

默认只保存告警。加上 `--all` 可以保留全部结果：

```powershell
ai-firewall analyze data/sample_flows.csv --all --output all-results.jsonl
```

### 2. 监控 Windows 实时连接

监控 60 秒：

```powershell
ai-firewall monitor --duration 60 --output live-alerts.jsonl
```

持续运行直到按下 `Ctrl+C`：

```powershell
ai-firewall monitor --duration 0
```

这个模式优先读取 `Get-NetTCPConnection`，没有权限时回退到 `netstat -ano`。它适合看新出现的 TCP 连接和进程，不等于完整的包级 IDS，也可能错过非常短的连接。

### 3. 打开本地仪表盘

```powershell
ai-firewall dashboard --input live-alerts.jsonl
```

然后访问 `http://127.0.0.1:8765`。仪表盘只绑定本机，不应该通过端口转发或反向代理公开到互联网。

### 4. 分析 PCAP / PCAPNG

```powershell
ai-firewall pcap capture.pcapng --output flows.csv --analyze
```

解析器读取包头和长度，不需要保存应用层载荷。当前支持 Ethernet、RAW IP、Linux cooked capture v1，以及常见 IPv4/IPv6 TCP、UDP 流量。只分析你有权查看的抓包文件；PCAP 仍可能包含 IP、域名和未加密内容，不能随便上传到公开仓库。

### 5. Windows 限时抓包

在管理员 PowerShell 中运行：

```powershell
ai-firewall capture --duration 30 --output capture.pcapng --analyze
```

这里使用 Windows 自带的 `pktmon`，时长被限制在 1 到 3600 秒。已有文件默认不会被覆盖。

### 6. 本机安全实验

```powershell
ai-firewall lab-simulate --confirm LOCAL-LAB --output lab-report.json
```

实验只允许访问 `127.0.0.1`，而且只能连接程序自己刚刚占用的临时端口。它会模拟正常访问、扫描形态、认证拒绝、连接突增、数据突增和可疑端口六种场景，但不会扫描局域网或公网，也不会使用真实密码、漏洞利用或恶意载荷。

我自己电脑上的一次脱敏结果记录在 [`docs/loopback-lab-results-v1.1.0.md`](docs/loopback-lab-results-v1.1.0.md)。这只能证明本机实验链路能工作，不能证明模型已经通过真实企业网络验收。

## 训练和评估

带标签的 CSV 可以用来训练逻辑回归模型：

```powershell
ai-firewall train data/sample_flows.csv --output models/trained-model.json
ai-firewall evaluate data/sample_flows.csv --model models/trained-model.json
```

评估会给出 Precision、Recall、False Positive Rate 以及 TP、FP、TN、FN。演示数据只适合检查代码流程，不能拿它的高分当作真实性能。

如果要对比三种模型，需要额外安装研究依赖：

```powershell
python -m pip install -e ".[comparison]"
ai-firewall compare-models labeled-flows.csv --output model-comparison.json
```

比较工具会按时间切分训练、校准和独立测试区间，尽量避免数据泄漏。它不会根据一次排名自动更换模型，更不会自动打开拦截。

### 论文复现实验

仓库现在还包含论文用的多随机种子实验入口。它会固定数据样本和时间切分，用 11、23、42、67、89 五个种子重复运行，在 0.5%、1% 和 2% 目标误报率下汇总均值与样本标准差；代表种子 42 可额外为 LightGBM 生成 Tree SHAP 全局图和逐告警解释。

```powershell
python -m pip install -e ".[comparison,explainability]"
ai-firewall research-multiseed converted-dataset.csv `
  --seed 11 --seed 23 --seed 42 --seed 67 --seed 89 `
  --with-shap --shap-seed 42 --shap-background-size 100 `
  --output-dir research-multiseed-results
```

实验协议与当前结果分别记录在 [`docs/paper-experiment-protocol.md`](docs/paper-experiment-protocol.md) 和 [`docs/research-results-2026-08-28.md`](docs/research-results-2026-08-28.md)。这组结果来自 CICIDS2017 与 UNSW-NB15 的公开数据样本，说明不同模型在时间漂移、误报控制和解释能力之间存在取舍；它不能代替真实目标网络的外部验收。SHAP 只解释当前 LightGBM 如何形成预测，不代表特征与攻击之间存在因果关系。

仓库还提供：

- `convert-dataset`：转换 CICIDS2017 或 UNSW-NB15；
- `research-experiment` / `research-multiseed`：生成单种子或多种子论文结果表、图和复现说明；
- `benchmark`：按时间切分并校准目标误报率；
- `baseline-gate`：检查授权、脱敏、独立留出和真实性能门槛；
- `performance-test`：记录 CPU、Python 内存、吞吐和延迟分位数；
- `review-feedback` / `retrain-feedback`：人工审核误报后受控再训练。

所有完整参数都可以通过下面的命令查看：

```powershell
ai-firewall --help
ai-firewall <command> --help
```

## 关于“防火墙”功能

这个部分我故意做得很保守。下面的命令默认只生成计划，不会修改系统：

```powershell
ai-firewall firewall-block 8.8.8.8 --duration 600
```

真正执行需要管理员权限、`--apply` 和准确的二次确认词。项目还带有默认允许名单、临时规则、到期清理、托管规则回滚和 kill switch。

即便如此，我仍然不建议为了演示而在日常电脑上执行真实封禁。当前代码没有让模型自动调用防火墙命令；这个边界是有意保留的。

## 数据和隐私

核心分析都在本机完成。项目不会主动上传 CSV、PCAP、告警、反馈或模型。

但“本地处理”不代表数据就不敏感：IP、域名、进程、时间戳和连接模式仍可能暴露个人或组织信息。真实日志、原始抓包、API key、Cookie、密码、签名私钥和未审查的性能报告都不应该提交到 GitHub。

## 怎么测试

安装全部可选测试依赖后运行：

```powershell
python -m pip install -e ".[comparison,explainability,updates]"
python -m unittest discover -s tests -v
```

当前本地完整运行结果为 66 项通过、2 项因缺少可选 `cryptography` 依赖而跳过。测试覆盖检测规则、模型训练、PCAP/PCAPNG、IPv6、Windows 连接监控、数据集转换、五随机种子汇总、SHAP 输出、仪表盘、反馈审核、防火墙安全边界、签名更新、性能报告和本机实验。

我认为真正重要的验收不是“样例 accuracy 很高”，而是：在已经授权、脱敏、跨多个日期、从未参与训练的数据上，误报和漏报是否仍然可接受。仓库已经有 `benchmark` 和 `baseline-gate` 工具，但没有公开真实私人网络数据，也没有声称真实环境门槛已经通过。

## 项目结构

```text
ai-firewall/
├── data/                       # 安全演示数据
├── models/                     # 启动模型
├── docs/                       # 实验记录
├── src/ai_firewall/
│   ├── cli.py                  # 命令行入口
│   ├── detector.py             # 模型与规则的混合评分
│   ├── features.py             # 特征提取
│   ├── rules.py                # 可解释规则
│   ├── pcap.py                 # PCAP / PCAPNG 解析
│   ├── windows_monitor.py      # Windows 实时连接监控
│   ├── dashboard.py            # 本地仪表盘
│   ├── feedback.py             # 反馈审核与受控再训练
│   ├── firewall.py             # 默认 dry-run 的防火墙控制
│   └── updates.py              # 签名模型更新与回滚
├── tests/                      # 自动化测试
├── SECURITY.md
└── README.md
```

## 目前还缺什么

- 还没有用公开仓库无法提供的长期真实个人/企业流量完成外部验收；
- Windows 实时连接表不是完整抓包，可能看不到非常短的连接和准确字节数；
- 规则和模型都可能误报，不能把风险分数当作攻击证据；
- 反馈训练仍要求人工审核，不能完全自动化；
- 防火墙响应没有在这次公开发布中对真实日常电脑做自动化执行验证；
- 这个项目不包含漏洞修复、恶意软件清除或完整终端防护能力。

接下来真正值得做的，不是继续堆很多听起来厉害的功能，而是收集经过授权和脱敏的跨日基线，在不同 Windows 设备上记录每日误报、漏报、CPU 占用和延迟，再根据结果调整模型和阈值。

## 安全边界

- 只监控你拥有或明确获准测试的设备与网络；
- 不要修改 loopback 实验去扫描其他目标；
- 不要把演示数据结果包装成真实防护能力；
- 不要把特征贡献解释成攻击因果证明；
- 不要未经人工确认就把反馈混入训练数据；
- 不要因为模型分数高就直接封禁地址；
- 如果需要报告安全问题，请阅读 [SECURITY.md](SECURITY.md)。

## License

MIT License，详见 [LICENSE](LICENSE)。
