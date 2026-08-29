# Research state — 2026-08-28

## Completed

- Implemented `research-multiseed` with seeds 11, 23, 42, 67, and 89.
- Kept the dataset sample and chronological 50% / 20% / 30% split fixed across seeds.
- Added mean, sample standard deviation, minimum, maximum, and per-seed CSV outputs.
- Added LightGBM Tree SHAP on representative seed 42 with 100 benign calibration background rows and a deterministic 2,000-row independent-test summary sample.
- Explained every LightGBM alert produced at any reported target FPR and generated global plus local plots.

## Main result at target FPR 1%

### CICIDS2017 — mean ± sample SD

- Logistic regression: test FPR 1.03% ± 0.85%, recall 84.48% ± 4.10%, F1 90.56% ± 1.94%, AUPRC 93.40% ± 3.13%.
- Hybrid logistic + rules: test FPR 0.01% ± 0.02%, recall 74.65% ± 3.84%, F1 85.43% ± 2.53%.
- LightGBM: test FPR 6.28%, recall 92.53%, F1 90.41%, AUPRC 96.31%; no seed variation because the current LightGBM configuration uses no stochastic row or feature subsampling.

### UNSW-NB15 — mean ± sample SD

- LightGBM: test FPR 1.03%, recall 92.51%, F1 93.99%, AUPRC 99.25%; no seed variation under the current deterministic configuration.
- Logistic regression: test FPR 0.55% ± 0.01%, recall 2.70% ± 1.55%, F1 5.11% ± 2.94%.
- Hybrid logistic + rules: test FPR 0.44% ± 0.25%, recall 2.70% ± 1.55%, F1 5.10% ± 2.93%.

## SHAP result

- CICIDS2017: 10,424 union alerts explained. Leading global features were `connections_60s`, `unique_dst_ports_60s`, and `duration_ms`.
- UNSW-NB15: 5,911 union alerts explained. Leading global features were `unique_dst_ports_60s`, `bytes_total`, and `connections_60s`.
- These are model-attribution results, not causal findings.

## Supported conclusion

No configuration dominates both datasets. LightGBM is strong and stable on UNSW-NB15 but misses the fixed-FPR target after temporal shift in CICIDS2017. The interpretable logistic/hybrid configurations work much better on CICIDS2017 than on UNSW-NB15 and show meaningful seed sensitivity. The defensible paper claim is therefore a performance–explainability–temporal-robustness trade-off, not universal superiority.

## Still pending before final paper submission

- Add IDS- and temporal-leakage-specific literature and supervisor-required sources.
- Decide whether the course expects additional rolling temporal windows or cross-dataset transfer beyond the fixed split.
- Write the paper from the generated tables and figures; do not describe these public benchmark results as production-network performance.
