# Research status — 2026-09-05

## Work completed

- Added `--lightgbm-grid-search` with 36 candidates, restricted to the outer training period.
- Prevented equal timestamps from crossing the outer or inner chronological boundaries.
- Re-ran `research-multiseed` with seeds 11, 23, 42, 67, and 89 using the same selected LightGBM parameters.
- Added mean, sample standard deviation, minimum, maximum, and per-seed CSV outputs.
- Added LightGBM Tree SHAP on representative seed 42 with 100 benign calibration background rows and a deterministic 2,000-row independent-test summary sample.
- Explained every LightGBM alert produced at any reported target FPR and generated global plus local plots.

## LightGBM grid search

- CICIDS2017 selected 400 estimators, learning rate 0.03, 31 leaves, and minimum child size 20; inner-validation FPR 0.93%, recall 60.93%, AUPRC 90.97%.
- UNSW-NB15 selected the predefined fallback of 100 estimators, learning rate 0.03, 31 leaves, and minimum child size 20. No candidate met the inner 1% FPR constraint; the selected candidate had 3.91% validation FPR, 100.00% recall, and 98.46% AUPRC.
- Outer calibration and independent-test periods were not accessed by the search algorithm.

## Results at the 1% target FPR

### CICIDS2017 — mean ± sample SD

- Logistic regression: test FPR 1.27% ± 0.95%, recall 83.57% ± 8.25%, F1 89.66% ± 4.57%, AUPRC 92.72% ± 5.94%.
- Hybrid logistic + rules: test FPR 0.05% ± 0.12%, recall 73.22% ± 7.56%, F1 84.31% ± 5.20%.
- LightGBM: test FPR 9.07%, recall 96.83%, F1 90.27%, AUPRC 97.75%; no seed variation because the selected configuration uses no stochastic row or feature subsampling.

### UNSW-NB15 — mean ± sample SD

- LightGBM: test FPR 1.001%, recall 91.50%, F1 93.51%, AUPRC 99.15%; no seed variation under the selected deterministic configuration.
- Logistic regression: test FPR 0.546% ± 0.002%, recall 3.41% ± 0.90%, F1 6.44% ± 1.64%.
- Hybrid logistic + rules: test FPR 0.546% ± 0.002%, recall 3.41% ± 0.90%, F1 6.44% ± 1.64%.

## SHAP summary

- CICIDS2017: 10,945 union alerts explained. Leading global features were `connections_60s`, `unique_dst_ports_60s`, and `avg_packet_bytes`.
- UNSW-NB15: 5,796 union alerts explained. Leading global features were `unique_dst_ports_60s`, `bytes_total`, and `packets`.
- These are model-attribution results, not causal findings.

## What these runs show

No configuration performs best on both datasets. The selected CICIDS2017 model met the inner FPR constraint but did not maintain it in the later test period. UNSW-NB15 showed the opposite pattern: no inner candidate met the constraint, while the refitted fallback later met the outer-test target. The current results show a performance–explainability–temporal-robustness trade-off rather than one model's general superiority.

## Remaining experiments

- Add rolling temporal windows and reserve a new, previously unused holdout.
- Run direct cross-dataset transfer after aligning a shared feature schema.
- Test richer rule-preserving fields and, after authorization, an anonymized local-network evaluation.
- Do not describe public-benchmark results as production-network performance.
