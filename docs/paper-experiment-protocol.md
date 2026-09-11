# 论文实验方案 / Paper experiment protocol

## 研究问题 / Research question

在相同的时间顺序训练、阈值校准和独立测试区间内，规则检测、逻辑回归、Isolation Forest、LightGBM，以及“逻辑回归 + 规则”的混合检测，能否在固定误报率下兼顾攻击召回率、解释覆盖率和运行效率？

Under the same chronological train, threshold-calibration, and independent-test intervals, can rule-based detection, logistic regression, Isolation Forest, LightGBM, and a logistic-plus-rule hybrid balance attack recall, explanation coverage, and efficiency at fixed false-positive rates?

## 实验约束 / Experimental controls

- 使用 CICIDS2017 与 UNSW-NB15，不把演示数据产生的指标写成论文结果。
- 先按时间排序，再按约 50% / 20% / 30% 切分训练、校准和测试数据；边界移到相同时间戳组的起点，保证同一时间戳不会跨区间。
- LightGBM 仅在外层训练时段内进行 36 组穷举网格搜索。外层训练段再按时间切成 60% 内部拟合、20% 内部阈值校准和 20% 内部验证；外层校准与最终测试不参与选参。
- 网格搜索候选为 `n_estimators=[100,200,400]`、`learning_rate=[0.03,0.05,0.10]`、`num_leaves=[15,31]`、`min_child_samples=[20,50]`。先筛选内部验证 FPR 不超过 1% 的候选，再按 Recall、AUPRC 和较低模型复杂度排序；如果没有候选满足约束，必须明确记录回退状态。
- 只使用校准区间的正常流量确定阈值，目标误报率为 0.5%、1% 和 2%。
- 五种配置使用相同测试记录和相同特征；随机模型使用 11、23、42、67、89 五个种子重复训练。时间切分和数据样本在五次运行中保持不变。
- 报告 Precision、Recall、F1、AUPRC、FPR、Recall/FPR 的 95% Wilson 区间、解释覆盖率、训练时间和批量 P95 打分延迟。
- 多种子表报告均值、样本标准差、最小值和最大值。种子间波动只衡量同一时间切分下的算法随机性，不能替代多时间窗口验证。
- 在代表种子 42 上使用 Tree SHAP 解释 LightGBM：100 条跨时间正常校准记录作为背景，2,000 条跨时间独立测试记录用于全局汇总，并解释所有目标 FPR 下预测告警的并集。
- 原始数据、转换后的大型 CSV 和模型缓存不提交 Git；只提交代码、实验协议、校验值清单和体积较小的最终表图。

## 运行方式 / Reproduction

安装可选模型依赖：

```powershell
python -m pip install -e ".[comparison,explainability]"
```

把公开数据转换为项目统一格式后，分别运行：

```powershell
ai-firewall research-multiseed <converted-dataset.csv> `
  --target-fpr 0.005 --target-fpr 0.01 --target-fpr 0.02 `
  --seed 11 --seed 23 --seed 42 --seed 67 --seed 89 `
  --lightgbm-grid-search `
  --with-shap --shap-seed 42 --shap-background-size 100 `
  --output-dir <result-directory>
```

网格搜索对每个数据集只执行一次，胜出参数随后固定用于五个种子。每个种子会生成完整 JSON、论文表格 CSV、两张可编辑 SVG 图和 `REPRODUCIBILITY.md`。根目录另外生成网格搜索 JSON/CSV/Markdown、多种子原始值、均值/样本标准差汇总和 Markdown 表。种子 42 还生成 SHAP 全局重要性 CSV、逐告警前三贡献 CSV、beeswarm、全局条形图以及真阳性/假阳性局部 waterfall 图。

## 局限 / Limitations

公开 IDS 数据集不能代表真实生产网络。批量墙钟延迟只描述当前电脑和当前软件版本。Isolation Forest 仍没有逐告警解释。LightGBM 的 SHAP 值解释的是当前拟合模型如何形成预测，不是网络特征导致攻击的因果证据。全局图不能代替逐告警解释。任何抽样、删行、类别合并或镜像下载都必须在论文中披露。
