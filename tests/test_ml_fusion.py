import json

import pytest

from common.features import build_feature_profile
from common.io import read_jsonl, write_jsonl
from ml.evaluate import evaluate
from ml.model import FUSION_ROUTES, load_bundle
from ml.train import FUSION_SOURCE, train


def _row(index, split, label=0, lab="xfh"):
    headers = {"Host": "127.0.0.1:8086", "User-Agent": f"FusionBrowser/{index % 3}", "Accept": "text/html"}
    if index % 2:
        headers["Cookie"] = "fusion_country=Vietnam"
    if label:
        headers["X-Forwarded-Host"] = "127.0.0.1:8087"
    return {
        "record_id": f"record-{index}", "request_id": f"request-{index}", "group": f"group-{index}",
        "split": split, "label": label, "label_name": "attack" if label else "normal", "lab": lab,
        "attack_type": "xfh-unkeyed-header" if label else "normal", "payload_variant": "test",
        "source": FUSION_SOURCE,
        "request": {"method": "GET", "uri": f"/labs/{lab}/shop?item={index}", "headers": headers, "body": ""},
    }


def test_fusion_train_and_evaluate_uses_profile_and_dataset_hash(tmp_path):
    rows = []
    for route_index, route in enumerate(FUSION_ROUTES):
        offset = route_index * 100
        rows += [_row(offset + index, "train", lab=route) for index in range(20)]
        rows += [_row(offset + index + 20, "validation", lab=route) for index in range(20)]
        rows += [_row(offset + 41, "test", lab=route)]
    rows += [_row(999, "test", label=1, lab="xfh")]
    dataset = tmp_path / "ml_dataset.jsonl"
    profile_path = tmp_path / "feature_profile.json"
    model_path = tmp_path / "model.joblib"
    out = tmp_path / "results"
    write_jsonl(dataset, rows)
    profile = build_feature_profile([row["request"] for row in rows if row["split"] == "train"])
    profile_path.write_text(json.dumps(profile), encoding="utf-8")

    metadata = train(dataset, profile_path, model_path, fpr_target=.05, n_estimators=20)
    assert metadata["train_count"] == 80
    assert load_bundle(model_path)["route_bundles"]["xfh"]["feature_profile"]["sample_count"] == 20
    result = evaluate(dataset, model_path, out)
    assert result["context"]["test_count"] == 5
    assert "iforest_has_measured_incremental_value" in result["contribution"]
    ml = next(metric for metric in result["metrics"] if metric["mode"] == "ml")
    assert ml["recall"] == 1
    assert (out / "classification_metrics.csv").is_file()
    assert (out / "route_classification_metrics.csv").is_file()
    assert (out / "iforest_contribution.json").is_file()

    changed = read_jsonl(dataset)
    changed[0]["request"]["uri"] = "/changed"
    write_jsonl(dataset, changed)
    with pytest.raises(ValueError, match="Dataset hash"):
        evaluate(dataset, model_path, out)
