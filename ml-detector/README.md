# Route aware ML shadow candidates

This workspace trains and evaluates per-route anomaly candidates for the local WCP lab. The active registry in [`config/model_registry.json`](config/model_registry.json) selects the model, threshold, feature schema, and normal profile for each route.

Candidates run in shadow mode. They do not choose cache behavior or block requests. The checked-in model packages are frozen candidate artifacts and are not promoted automatically.

## Evaluation

Read the [dataset card](DATASET_CARD.md) for generation, splits, sample counts, privacy, and limitations. The [route evaluation report](DETECTOR_EVALUATION.md) compares route-specific rule, profile, IF, and hybrid decisions; includes structural/relationship IF ablation; and reports precision, recall, F1, FPR, and support for held-out and independent synthetic variant sets.

To score locally available datasets:

```powershell
python scripts/replay_ml_evaluation.py --markdown-output ml-detector/DETECTOR_EVALUATION.md
```

From a clean checkout, start the lab on port `8086` and use `--collect --blind` to regenerate datasets before scoring:

```powershell
docker compose up -d --build
python scripts/replay_ml_evaluation.py --collect --blind --markdown-output ml-detector/DETECTOR_EVALUATION.md
```

The command refuses to overwrite generated data or blind evidence. It records run ID, commit, machine details, sample support, and dataset/model fingerprints. All reported traffic is synthetic; independent blind variants are not production OOD evidence.

The historical audit snapshots are not aggregated because they use incompatible candidate sets and run configurations. See the project [evaluation note](../docs/EVALUATION.md) before using a metric in a portfolio or report.
