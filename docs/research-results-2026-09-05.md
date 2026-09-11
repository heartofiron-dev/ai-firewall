# Grid-searched five-seed public-dataset results — 2026-09-05

These results use public benchmark samples and should not be read as production performance. Equal-timestamp groups remain on the same side of every boundary, producing separate chronological train, calibration, and independent-test periods. LightGBM was tuned through 36 candidate configurations inside the outer training period only; the outer calibration and test periods were not accessed during search.

## Data and outer split

| Dataset | Sample | Train | Calibration | Test | Test benign / attack |
|---|---:|---:|---:|---:|---:|
| CICIDS2017 | 88,459 | 44,221 | 17,587 | 26,651 | 17,624 / 9,027 |
| UNSW-NB15 | 97,695 | 48,846 | 19,540 | 29,309 | 23,675 / 5,634 |

CICIDS2017 was retrieved from the `bvsam/cic-ids-2017` traffic-label Parquet mirror and verified against repository LFS SHA-256 objects. UNSW-NB15 came from Zenodo DOI `10.5281/zenodo.10140548`, with all four raw CSV partitions matching the published MD5 values. Raw and converted datasets are not included in the public repository.

## Nested chronological grid search

The outer training period was split into 60% inner fitting, 20% benign-only threshold calibration, and 20% validation. The grid crossed `n_estimators=[100,200,400]`, `learning_rate=[0.03,0.05,0.10]`, `num_leaves=[15,31]`, and `min_child_samples=[20,50]`. Candidates meeting validation FPR <= 1% were ranked by recall, AUPRC, and lower complexity. If none met the constraint, the predefined fallback minimized FPR overshoot before applying the remaining tie-breaks.

| Dataset | Selected parameters | Validation FPR | Recall | AUPRC | Constraint |
|---|---|---:|---:|---:|---|
| CICIDS2017 | 400 estimators; 0.03 learning rate; 31 leaves; child 20 | 0.93% | 60.93% | 90.97% | Met |
| UNSW-NB15 | 100 estimators; 0.03 learning rate; 31 leaves; child 20 | 3.91% | 100.00% | 98.46% | Not met; fallback |

The UNSW-NB15 fallback must not be described as satisfying the inner-validation 1% constraint, even though its refitted outer-test FPR later reached 1.001%.

## Independent-test results at the 1% calibration target

Values are mean +/- sample standard deviation over seeds 11, 23, 42, 67, and 89.

| Dataset | Configuration | Test FPR | Precision | Recall | F1 | AUPRC |
|---|---|---:|---:|---:|---:|---:|
| CICIDS2017 | Logistic regression | 1.27% +/- 0.95% | 97.23% +/- 1.80% | 83.57% +/- 8.25% | 89.66% +/- 4.57% | 92.72% +/- 5.94% |
| CICIDS2017 | Hybrid logistic + rules | 0.05% +/- 0.12% | 99.87% +/- 0.29% | 73.22% +/- 7.56% | 84.31% +/- 5.20% | 86.63% +/- 3.75% |
| CICIDS2017 | LightGBM | 9.07% | 84.54% | 96.83% | 90.27% | 97.75% |
| CICIDS2017 | Isolation Forest | 4.10% +/- 1.03% | 4.59% +/- 3.91% | 0.40% +/- 0.32% | 0.74% +/- 0.59% | 63.11% +/- 2.48% |
| UNSW-NB15 | LightGBM | 1.001% | 95.60% | 91.50% | 93.51% | 99.15% |
| UNSW-NB15 | Logistic regression | 0.546% +/- 0.002% | 58.93% +/- 6.73% | 3.41% +/- 0.90% | 6.44% +/- 1.64% | 42.80% +/- 2.88% |
| UNSW-NB15 | Hybrid logistic + rules | 0.546% +/- 0.002% | 58.93% +/- 6.73% | 3.41% +/- 0.90% | 6.44% +/- 1.64% | 39.89% +/- 2.19% |
| UNSW-NB15 | Isolation Forest | 1.09% +/- 0.05% | 25.28% +/- 9.32% | 1.67% +/- 1.06% | 3.13% +/- 1.92% | 46.41% +/- 6.07% |

Rule-only produced no alerts in either test period. LightGBM has zero seed variance because row and feature subsampling were disabled; this is deterministic repeatability under one fixed split, not temporal stability.

## Tree SHAP

- CICIDS2017: 10,945 union alerts explained; leading features were `connections_60s`, `unique_dst_ports_60s`, and `avg_packet_bytes`.
- UNSW-NB15: 5,796 union alerts explained; leading features were `unique_dst_ports_60s`, `bytes_total`, and `packets`.
- Tree SHAP describes fitted-model attribution, not attack causation, and cannot justify automatic blocking by itself.

## Limitations

- The selected CICIDS2017 configuration met the inner constraint but reached 9.07% FPR in the later outer test, showing that the calibrated threshold did not transfer to that period.
- No UNSW-NB15 candidate met the inner constraint, while the selected fallback later met the outer-test target; this reversal also shows period sensitivity.
- The same outer test periods had been examined in earlier fixed-parameter runs. The grid-search algorithm did not access them, but this is a comparative result rather than a confirmatory test on an untouched holdout.
- Five seeds do not replace rolling-window, direct-transfer, or authorized local-network evaluation.

These runs support a performance-explainability-temporal-robustness trade-off. They do not establish a universally superior detector or a production-ready firewall.
