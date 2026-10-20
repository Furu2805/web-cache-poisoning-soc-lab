import json

from common.io import read_jsonl, write_jsonl
from traffic.fusion_features import prepare_features


def _row(index, label, split, headers=None):
    return {
        "record_id": f"record-{index}",
        "request_id": f"request-{index}",
        "group_id": f"group-{index}",
        "split": split,
        "label": label,
        "lab": "xfh",
        "attack_type": "normal" if label == "normal" else "xfh-unkeyed-header",
        "payload_variant": "test",
        "request": {
            "method": "GET",
            "uri": f"/labs/xfh/shop?cb={index}",
            "headers": headers or {"Host": "127.0.0.1:8086", "User-Agent": "TestBrowser"},
            "body": "",
        },
        "observation": {"cache_status": "MISS"},
    }


def test_fusion_adapter_is_normal_only_and_request_only(tmp_path):
    rows = [
        _row(1, "normal", "train"),
        _row(2, "normal", "validation"),
        _row(3, "normal", "test"),
        _row(4, "attack", "train", {"Host": "127.0.0.1:8086", "X-Forwarded-Host": "127.0.0.1:8087"}),
    ]
    source = tmp_path / "raw.jsonl"
    output = tmp_path / "processed"
    write_jsonl(source, rows)
    manifest = prepare_features(source, output)
    adapted = read_jsonl(output / "ml_dataset.jsonl")

    assert manifest["split_label_counts"] == {
        "train:normal": 1, "validation:normal": 1, "test:normal": 1, "test:attack": 1,
    }
    assert next(row for row in adapted if row["label_name"] == "attack")["split"] == "test"
    assert all("observation" not in row for row in adapted)
    profile = json.loads((output / "feature_profile.json").read_text(encoding="utf-8"))
    assert "x-forwarded-host" in profile["rare_headers"]
    header = (output / "features.csv").read_text(encoding="utf-8").splitlines()[0]
    assert "request_id" in header and "rare_header_count" in header
