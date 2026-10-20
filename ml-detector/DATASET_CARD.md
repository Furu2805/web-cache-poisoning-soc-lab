# Route detector dataset card

## Purpose

These datasets evaluate frozen, route-specific anomaly detector candidates for the local Web Cache Poisoning lab. They cover four intentionally vulnerable request paths: unkeyed `X-Forwarded-Host` (XFH), reflected query payloads, UTM callback cloaking, and GET requests with bodies (Fat GET).

All traffic is generated against the local synthetic lab at `http://127.0.0.1:8086`. It is not production traffic and does not represent production prevalence, benign request diversity, attacker behavior, proxy configurations, or analyst labels.

## Sources and generation

| Route | Collector | Seed | Feature count | Normal variants | Attack variants |
| --- | --- | ---: | ---: | ---: | ---: |
| XFH v3 | `src/collect_xfh_candidate_v3.py` | `20270817` | 546 | 80 | 5 |
| Query v8 | `src/collect_query_candidate_v8.py` | `20270629` | 553 | 6 | 5 |
| UTM phase 3 | `src/collect_utm_dataset.py` | `20261005` | 556 | 12 | 5 |
| Fat GET v2 | `src/collect_fatget_candidate_v2.py` | `20270921` | 554 | 64 | 5 |

Collectors create benign and attack scenarios from fixed seeds, send them through the local lab, extract request-time numeric features, and write manifests with sample counts and SHA-256 hashes. Attack labels come from the scenario definitions; the collectors also check the expected lab effect for the attack records. The known vulnerable route is used; fixed routes are excluded from these model datasets.

## Split and counts

Splitting is by request session/group. Training and validation contain normal requests only; attack examples are held out until the final test split. Each route has 1,000 held-out normal and 1,000 held-out attack samples.

| Route | Train normal | Validation normal | Test normal | Test attack | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| XFH v3 | 8,000 | 2,000 | 1,000 | 1,000 | 12,000 |
| Query v8 | 8,000 | 2,000 | 1,000 | 1,000 | 12,000 |
| UTM phase 3 | 5,000 | 1,000 | 1,000 | 1,000 | 8,000 |
| Fat GET v2 | 8,000 | 2,000 | 1,000 | 1,000 | 12,000 |
| **Total** | **29,000** | **7,000** | **4,000** | **4,000** | **44,000** |

The evaluation command checks that group IDs do not cross train, validation, and test splits. It also checks that training and validation are normal-only and that each test set contains both classes. The generated blind sets are collected separately from candidate training and threshold calibration and evaluated as independent synthetic variant holdouts.

## Features and privacy

The candidate inputs are request-time numeric feature vectors. Raw query values, request bodies, host values, cookies, and response/evidence fields are excluded from the processed feature records used for training and scoring. The blind records may contain separate evidence metadata; the evaluator ignores it and requires its separation from the feature object.

The local collection process may temporarily write raw request material under `ml-detector/data/raw/`. That directory and generated datasets are ignored by Git. Do not publish those local raw files or blind evidence with the repository.

## Intended use and limitations

- Compare the frozen route candidate with a narrow, route-specific rule and the candidate's normal-profile guard.
- Report precision, recall, F1, false-positive rate (FPR), and normal/attack support per route and split.
- Ablate the structural and relationship Isolation Forest components where the candidate has both.
- Check behavior on independently generated variants from the same lab.

The rule baseline is deliberately tied to the known lab primitive; it is not a general WAF rule set. For XFH and Fat GET, the frozen normal-profile guard is itself the explicit primitive rule, so their rule and profile results are expected to match. The blind sets are synthetic novelty holdouts, not externally sourced or production OOD data. No production efficacy or false-positive rate is implied.

## Reproduce

Use a clean checkout, Python dependencies from the repository requirements, and the local lab on port `8086`:

```powershell
python -m venv .venv-ml
.venv-ml\Scripts\python -m pip install -r requirements.txt
docker compose up -d --build
.venv-ml\Scripts\python scripts/replay_ml_evaluation.py --collect --blind --markdown-output ml-detector/DETECTOR_EVALUATION.md
```

The replay command calls the four fixed-seed development collectors, then the independent blind collectors, and scores the checked-in frozen candidates. It refuses to overwrite existing generated data or blind evidence. To evaluate data already collected locally, omit `--collect --blind`:

```powershell
.venv-ml\Scripts\python scripts/replay_ml_evaluation.py --markdown-output ml-detector/DETECTOR_EVALUATION.md
```

On Linux/macOS, replace `.venv-ml\Scripts\python` with `.venv-ml/bin/python`. Each evaluation writes a run ID, source commit, working-tree state, environment, dataset and candidate hashes, counts, and route-level metrics. Fresh collection gets new dataset fingerprints; retain the generated JSON report with its run ID when citing a result.

The tracked report at [`DETECTOR_EVALUATION.md`](DETECTOR_EVALUATION.md) is one local synthetic run, not a permanent benchmark claim.
