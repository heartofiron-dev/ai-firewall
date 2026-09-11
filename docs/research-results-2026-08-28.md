# Five-seed public-dataset results — 2026-08-28

These results use fixed chronological samples from two public datasets; they do not measure production performance. Every run used the same 50% train / 20% calibration / 30% independent-test split. Thresholds were calibrated only on benign calibration rows at target false-positive rates (FPRs) of 0.5%, 1%, and 2%.

## Data

| Dataset | Sample | Train | Calibration | Test | Test benign / attack |
|---|---:|---:|---:|---:|---:|
| CICIDS2017 | 88,459 | 44,229 | 17,692 | 26,538 | 17,511 / 9,027 |
| UNSW-NB15 | 97,695 | 48,847 | 19,539 | 29,309 | 23,675 / 5,634 |

CICIDS2017 was retrieved from the `bvsam/cic-ids-2017` traffic-label Parquet mirror because the official CIC endpoint required personal registration. The source files were SHA-256 verified against their repository LFS objects. UNSW-NB15 was retrieved from Zenodo DOI `10.5281/zenodo.10140548`; all four raw CSV partitions matched the published MD5 values.

The CIC mirror contained 288,602 all-null padded rows and 115 negative-duration rows. They were excluded rather than imputed. UNSW-NB15 contained two rows with invalid required values, which were also excluded. Raw and converted datasets are intentionally not included in this repository.

## Independent test results at the 1% calibration target

Values are mean ± sample standard deviation over seeds 11, 23, 42, 67, and 89. The sample and chronological split were fixed, so these deviations measure stochastic model instability only—not uncertainty about deployment performance or temporal generalization.

| Dataset | Configuration | Test FPR | Precision | Recall | F1 | AUPRC |
|---|---|---:|---:|---:|---:|---:|
| CICIDS2017 | Logistic regression | 1.03% ± 0.85% | 97.75% ± 1.67% | 84.48% ± 4.10% | 90.56% ± 1.94% | 93.40% ± 3.13% |
| CICIDS2017 | Hybrid logistic + rules | 0.01% ± 0.02% | 99.98% ± 0.05% | 74.65% ± 3.84% | 85.43% ± 2.53% | 87.41% ± 1.89% |
| CICIDS2017 | LightGBM | 6.28% ± 0.00% | 88.37% ± 0.00% | 92.53% ± 0.00% | 90.41% ± 0.00% | 96.31% ± 0.00% |
| CICIDS2017 | Isolation Forest | 4.07% ± 1.05% | 4.64% ± 3.95% | 0.40% ± 0.32% | 0.74% ± 0.59% | 64.01% ± 2.55% |
| UNSW-NB15 | LightGBM | 1.03% ± 0.00% | 95.53% ± 0.00% | 92.51% ± 0.00% | 93.99% ± 0.00% | 99.25% ± 0.00% |
| UNSW-NB15 | Logistic regression | 0.55% ± 0.01% | 47.42% ± 26.65% | 2.70% ± 1.55% | 5.11% ± 2.94% | 40.81% ± 4.72% |
| UNSW-NB15 | Hybrid logistic + rules | 0.44% ± 0.25% | 47.39% ± 26.64% | 2.70% ± 1.55% | 5.10% ± 2.93% | 39.47% ± 1.14% |
| UNSW-NB15 | Isolation Forest | 1.09% ± 0.05% | 25.28% ± 9.32% | 1.67% ± 1.06% | 3.13% ± 1.92% | 46.41% ± 6.07% |

Rule-only produced no alerts in either independent-test interval. LightGBM has zero seed variance here because the current configuration does not use stochastic row or feature subsampling; this is deterministic repeatability, not evidence that it will remain stable under a different time window or network.

The machine-readable means and standard deviations are in [`research-primary-metrics-2026-08-28.csv`](research-primary-metrics-2026-08-28.csv).

## SHAP analysis

Tree SHAP was run for LightGBM on representative seed 42 using 100 benign calibration rows as the background distribution and a deterministic 2,000-row independent-test sample for global summaries. Every LightGBM alert appearing at any reported target FPR was explained:

- CICIDS2017: 10,424 union alerts; leading global features were `connections_60s`, `unique_dst_ports_60s`, and `duration_ms`.
- UNSW-NB15: 5,911 union alerts; leading global features were `unique_dst_ports_60s`, `bytes_total`, and `connections_60s`.

SHAP attributes the fitted model's prediction to its inputs. It does not show that a feature caused an attack, and it does not turn the detector into an automatic blocking decision.

## Limitations

- No configuration dominates both datasets.
- LightGBM reaches 92.51% recall at 1.03% FPR on UNSW-NB15, but its CICIDS2017 independent-test FPR rises to 6.28% after calibration to a 1% target.
- Logistic regression and the hybrid configuration have higher recall on CICIDS2017 than on UNSW-NB15, where recall falls below 3% and varies across seeds.
- Rule-only does not transfer to these converted samples because the required rule triggers are absent or not preserved in the benchmark fields.
- Five seeds do not replace rolling-window or cross-dataset evaluation; the time split remained fixed.
- Public IDS benchmarks cannot establish real-network or production performance.

These results support a paper on the **performance–explainability–temporal-robustness trade-off in hybrid network intrusion detection**. They do not establish a universally superior model or a production-ready firewall.

