"""Evaluate the Fusion model once on the untouched held-out test split."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay, confusion_matrix, f1_score, precision_score, recall_score

from common.features import rule_reasons
from common.io import read_jsonl
from ml.model import FUSION_ROUTES, inspect_request, load_bundle, select_component
from ml.train import DEFAULT_DATASET, DEFAULT_MODEL, FUSION_SOURCE


# Tính checksum dataset/model để gắn vào evidence đánh giá.
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Tính confusion matrix và precision/recall/FPR cho một biến thể.
def _metric_row(name: str, y: np.ndarray, prediction: np.ndarray) -> dict[str, object]:
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    return {
        "mode": name, "TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp),
        "precision": precision_score(y, prediction, zero_division=0),
        "recall": recall_score(y, prediction, zero_division=0),
        "f1": f1_score(y, prediction, zero_division=0),
        "fpr": fp / max(1, fp + tn), "fnr": fn / max(1, fn + tp),
        "normal_support": int((y == 0).sum()), "attack_support": int((y == 1).sum()),
    }


# Ghi hình confusion matrix để kiểm tra kết quả.
def _write_confusion(path: Path, title: str, y: np.ndarray, pred: np.ndarray) -> None:
    figure, axis = plt.subplots(figsize=(4, 4))
    ConfusionMatrixDisplay.from_predictions(y, pred, labels=[0, 1], display_labels=["Normal", "Attack"], ax=axis, colorbar=False)
    axis.set_title(title)
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    plt.close(figure)


# Đánh giá Baseline trên tập test mà không fit lại model.
def evaluate(dataset=DEFAULT_DATASET, model_path=DEFAULT_MODEL, output_dir="results"):
    dataset, model_path, output_dir = map(Path, (dataset, model_path, output_dir))
    rows = read_jsonl(dataset)
    if not rows or any(row.get("source") != FUSION_SOURCE for row in rows):
        raise ValueError("Evaluation requires the Fusion adapter dataset")
    if any("observation" in row or "response" in row for row in rows):
        raise ValueError("Evaluation dataset must be request-only")
    groups = {split: {row["group"] for row in rows if row["split"] == split} for split in ("train", "validation", "test")}
    if groups["train"] & groups["validation"] or groups["train"] & groups["test"] or groups["validation"] & groups["test"]:
        raise ValueError("Group leakage between splits")
    test_rows = [row for row in rows if row["split"] == "test"]
    if not test_rows or not any(row["label"] == 0 for row in test_rows) or not any(row["label"] == 1 for row in test_rows):
        raise ValueError("Held-out test data must contain normal and attack samples")

    bundle = load_bundle(model_path)
    if bundle.get("dataset_sha256") != _sha256(dataset):
        raise ValueError("Dataset hash differs from the model training dataset; retrain before evaluation")
    y = np.asarray([row["label"] for row in test_rows], dtype=int)
    selected = [select_component(bundle, row["request"]) for row in test_rows]
    inspected = [inspect_request(bundle, row["request"]) for row in test_rows]
    scores = np.asarray([item[0] for item in inspected])
    iforest = np.asarray([item[1] for item in inspected])
    profile_reasons = [item[2] for item in inspected]
    model_routes = [item[0] for item in selected]
    thresholds = np.asarray([item[1]["threshold"] for item in selected], dtype=float)
    profile = np.asarray([bool(reasons) for reasons in profile_reasons])
    rule = np.asarray([bool(rule_reasons(row["request"])) for row in test_rows])
    # ``ml`` is the normal-only detector decision: Isolation Forest OR the
    # normal-envelope guard fit from exactly the same train-normal records.
    ml = iforest | profile
    predictions = {"rule": rule, "iforest": iforest, "profile": profile, "ml": ml, "hybrid": rule | ml}

    # A combined result can look successful even if IF never changes a
    # verdict. Record its exclusive contribution explicitly so a later model
    # promotion cannot claim an ML benefit that the held-out data does not
    # support. These arrays are diagnostic ablations, not extra runtime modes.
    iforest_only = iforest & ~profile
    profile_only = profile & ~iforest

    output_dir.mkdir(parents=True, exist_ok=True)
    metrics, per_type = [], []
    attack_types = sorted({str(row["attack_type"]) for row in test_rows if row["label"] == 1})
    variants = sorted({(str(row["lab"]), str(row["attack_type"]), str(row["payload_variant"])) for row in test_rows if row["label"] == 1})
    for name, prediction in predictions.items():
        metrics.append(_metric_row(name, y, prediction))
        _write_confusion(output_dir / f"confusion_{name}.png", name, y, prediction)
        for attack_type in attack_types:
            mask = np.asarray([row["attack_type"] == attack_type for row in test_rows])
            per_type.append({"mode": name, "lab": next(row["lab"] for row in test_rows if row["attack_type"] == attack_type), "attack_type": attack_type, "payload_variant": "all", "total": int(mask.sum()), "detected": int(prediction[mask].sum()), "detection_rate": float(prediction[mask].mean())})
        for lab, attack_type, variant in variants:
            mask = np.asarray([row["lab"] == lab and row["attack_type"] == attack_type and row["payload_variant"] == variant for row in test_rows])
            per_type.append({"mode": name, "lab": lab, "attack_type": attack_type, "payload_variant": variant, "total": int(mask.sum()), "detected": int(prediction[mask].sum()), "detection_rate": float(prediction[mask].mean())})

    detail = pd.DataFrame({
        "record_id": [row["record_id"] for row in test_rows], "request_id": [row["request_id"] for row in test_rows],
        "lab": [row["lab"] for row in test_rows], "label": y, "label_name": [row["label_name"] for row in test_rows],
        "attack_type": [row["attack_type"] for row in test_rows], "payload_variant": [row["payload_variant"] for row in test_rows],
        "model_route": model_routes,
        "anomaly_score": scores, "threshold": thresholds, "score_excess": scores - thresholds,
        "rule_reasons": [";".join(rule_reasons(row["request"])) for row in test_rows],
        "profile_reasons": [";".join(reasons) for reasons in profile_reasons],
        **{name: value.astype(int) for name, value in predictions.items()},
    })
    pd.DataFrame(metrics).to_csv(output_dir / "classification_metrics.csv", index=False)
    pd.DataFrame(per_type).to_csv(output_dir / "detection_by_type.csv", index=False)
    detail.to_csv(output_dir / "predictions.csv", index=False)
    for name, prediction in predictions.items():
        detail[(detail.label == 0) & (prediction == 1)].to_csv(output_dir / f"false_positives_{name}.csv", index=False)
        detail[(detail.label == 1) & (prediction == 0)].to_csv(output_dir / f"false_negatives_{name}.csv", index=False)

    route_metrics = []
    route_contribution = {}
    for route in FUSION_ROUTES:
        mask = np.asarray([row["lab"] == route for row in test_rows])
        route_metrics.append({"route": route, **_metric_row("iforest", y[mask], iforest[mask])})
        route_metrics.append({"route": route, **_metric_row("profile", y[mask], profile[mask])})
        route_metrics.append({"route": route, **_metric_row("ml", y[mask], ml[mask])})
        route_iforest_only = iforest[mask] & ~profile[mask]
        route_contribution[route] = {
            "iforest_only_true_positives": int(((y[mask] == 1) & route_iforest_only).sum()),
            "iforest_only_false_positives": int(((y[mask] == 0) & route_iforest_only).sum()),
            "iforest_recall": float(recall_score(y[mask], iforest[mask], zero_division=0)),
        }
    pd.DataFrame(route_metrics).to_csv(output_dir / "route_classification_metrics.csv", index=False)

    figure, axis = plt.subplots(figsize=(7, 4))
    for label, title in ((0, "Normal"), (1, "Attack")):
        axis.hist(scores[y == label], bins=25, alpha=.55, label=title)
    for route in sorted(set(model_routes)):
        route_threshold = float(next(thresholds[index] for index, value in enumerate(model_routes) if value == route))
        axis.axvline(route_threshold, linestyle="--", label=f"{route} validation threshold")
    axis.set_xlabel("Anomaly score (higher = more anomalous, not probability)")
    axis.set_ylabel("Requests")
    axis.legend()
    figure.tight_layout()
    figure.savefig(output_dir / "score_distribution.png", dpi=160)
    plt.close(figure)

    frame = pd.DataFrame(metrics).set_index("mode")
    axis = frame[["precision", "recall", "f1", "fpr"]].plot.bar(figsize=(8, 4), ylim=(0, 1))
    axis.set_ylabel("Ratio")
    axis.figure.tight_layout()
    axis.figure.savefig(output_dir / "model_comparison.png", dpi=160)
    plt.close(axis.figure)
    context = {
        "source": "synthetic local Fusion lab; request-only features", "dataset": str(dataset).replace("\\", "/"),
        "dataset_sha256": _sha256(dataset), "model": str(model_path).replace("\\", "/"),
        "model_training_dataset_sha256": bundle["dataset_sha256"], "test_count": len(test_rows),
        "test_normal_count": int((y == 0).sum()), "test_attack_count": int((y == 1).sum()),
        "attack_prevalence": float(y.mean()),
        "route_thresholds": {route: float(bundle["route_bundles"][route]["threshold"]) for route in FUSION_ROUTES},
        "validation_fpr_target": bundle["fpr_target"],
        "validation_observed_fpr": {route: float(bundle["route_bundles"][route]["validation_observed_fpr"]) for route in FUSION_ROUTES},
        "score_convention": bundle["score_convention"],
        "test_policy": "held-out evaluation only; no threshold or rule tuning performed here",
        "note": "The synthetic attack prevalence is not a production precision estimate. Classification is separate from end-to-end poisoning success.",
    }
    contribution = {
        "schema": "fusion-iforest-contribution-v1",
        "purpose": "Held-out ablation of Isolation Forest beyond normal-profile; not a runtime decision.",
        "iforest_only_trigger_count": int(iforest_only.sum()),
        "iforest_only_true_positives": int(((y == 1) & iforest_only).sum()),
        "iforest_only_false_positives": int(((y == 0) & iforest_only).sum()),
        "profile_only_trigger_count": int(profile_only.sum()),
        "profile_only_true_positives": int(((y == 1) & profile_only).sum()),
        "profile_only_false_positives": int(((y == 0) & profile_only).sum()),
        "combined_true_positives": int(((y == 1) & ml).sum()),
        "combined_false_positives": int(((y == 0) & ml).sum()),
        "iforest_has_measured_incremental_value": bool(((y == 1) & iforest_only).any()),
        "promotion_gate": "Require at least one IF-only held-out true positive and review IF-only false positives before claiming IF contributes to the final detector.",
        "route_contribution": route_contribution,
        "xfh_iforest_recall": route_contribution["xfh"]["iforest_recall"],
    }
    (output_dir / "evaluation_context.json").write_text(json.dumps(context, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output_dir / "iforest_contribution.json").write_text(json.dumps(contribution, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(pd.DataFrame(metrics).to_string(index=False))
    print(json.dumps(contribution, ensure_ascii=False, indent=2))
    return {"metrics": metrics, "context": context, "contribution": contribution}


# Đọc CLI rồi chạy evaluation.
def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Fusion Isolation Forest on held-out test data")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    args = parser.parse_args()
    evaluate(args.dataset, args.model, args.output_dir)


if __name__ == "__main__":
    main()
