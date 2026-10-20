"""Validate and prepare privacy-preserving WCP request records for IF.

This adapter accepts only ``wcp-request-record-v1`` records. It deliberately
does not read evidence fields into the processed feature dataset: cache state,
response size, effect verification, labels and correlation IDs are metadata,
never Isolation Forest inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import fmean


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "ml-detector" / "data" / "raw" / "requests.jsonl"
DEFAULT_OUTPUT = ROOT / "ml-detector" / "data" / "processed"
DEFAULT_REGISTRY = ROOT / "ml-detector" / "config" / "route_registry.json"
DEFAULT_MANIFEST = ROOT / "ml-detector" / "data" / "manifests"
RAW_SCHEMA = "wcp-request-record-v1"
PROCESSED_SCHEMA = "wcp-processed-features-v1"
PROFILE_SCHEMA = "wcp-route-normal-profile-v1"


# Đọc các record JSONL phục vụ huấn luyện hoặc đánh giá.
def read_jsonl(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


# Ghi từng record thành một dòng JSONL.
def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


# Nạp registry cấu hình route và feature schema.
def load_registry(path: Path) -> dict[str, object]:
    registry = json.loads(path.read_text(encoding="utf-8"))
    routes = registry.get("routes")
    if registry.get("schema_version") != "wcp-route-registry-v1" or not isinstance(routes, dict):
        raise ValueError("invalid WCP route registry")
    if set(routes) != {"xfh", "query", "utm", "fatget"}:
        raise ValueError("route registry must contain exactly xfh, query, utm and fatget")
    return registry


# Lấy thứ tự feature được khai báo trong record/schema.
def _feature_names(record: dict[str, object]) -> tuple[str, ...]:
    request_features = record["request_features"]
    if not isinstance(request_features, dict):
        raise ValueError("request_features must be an object")
    structural = request_features.get("structural")
    lexical_hash = request_features.get("lexical_hash")
    if not isinstance(structural, dict) or not isinstance(lexical_hash, dict):
        raise ValueError("request_features must contain structural and lexical_hash objects")
    names = tuple(structural) + tuple(lexical_hash)
    if len(names) != len(set(names)) or len(structural) != 25 or len(lexical_hash) != 96:
        raise ValueError("unexpected request-time feature dimensions")
    return names


# Kiểm tra và chuyển feature record thành vector số đúng schema.
def _vector(record: dict[str, object], feature_names: tuple[str, ...]) -> dict[str, float]:
    request_features = record["request_features"]
    source = {**request_features["structural"], **request_features["lexical_hash"]}
    if set(source) != set(feature_names):
        raise ValueError("feature schema differs between records")
    vector = {name: float(source[name]) for name in feature_names}
    if not all(math.isfinite(value) for value in vector.values()):
        raise ValueError("feature vector contains a non-finite value")
    return vector


# Kiểm tra schema, label và split của các record đầu vào.
def validate_records(records: list[dict[str, object]], registry: dict[str, object]) -> tuple[str, ...]:
    if not records:
        raise ValueError("raw requests.jsonl is empty; run the local collector first")
    routes = registry["routes"]
    feature_names = _feature_names(records[0])
    seen_record_ids: set[str] = set()
    seen_request_ids: set[str] = set()
    group_split: dict[str, str] = {}
    route_split_label = Counter()
    for index, record in enumerate(records):
        if record.get("schema_version") != RAW_SCHEMA:
            raise ValueError(f"record {index} has an unsupported schema version")
        for name in ("record_id", "collection", "route", "annotation", "request_features", "evidence", "feature_policy"):
            if name not in record:
                raise ValueError(f"record {index} is missing {name}")
        record_id = str(record["record_id"])
        if not record_id or record_id in seen_record_ids:
            raise ValueError("record_id must be non-empty and unique")
        seen_record_ids.add(record_id)

        route = record["route"]
        annotation = record["annotation"]
        collection = record["collection"]
        evidence = record["evidence"]
        if not all(isinstance(value, dict) for value in (route, annotation, collection, evidence)):
            raise ValueError(f"record {index} has an invalid metadata object")
        route_id = str(route.get("id", ""))
        route_definition = routes.get(route_id)
        if not isinstance(route_definition, dict) or route.get("scenario") != route_definition.get("scenario"):
            raise ValueError(f"record {index} does not match the route registry")
        if route.get("variant") != "vulnerable":
            raise ValueError("fixed routes are excluded from the ML dataset")
        label = annotation.get("label")
        split = annotation.get("split")
        if label not in {"normal", "attack"} or split not in {"train", "validation", "test"}:
            raise ValueError(f"record {index} has an invalid label/split")
        if label == "attack":
            if split != "test" or annotation.get("attack_type") != route_definition.get("attack_type"):
                raise ValueError("attack records must be route-matched held-out test data")
        elif annotation.get("attack_type") != "normal":
            raise ValueError("normal records must have attack_type=normal")
        group_id = str(collection.get("group_id", ""))
        if not group_id:
            raise ValueError("group_id is required for leakage checks")
        previous_split = group_split.setdefault(group_id, str(split))
        if previous_split != split:
            raise ValueError("group leakage across splits")
        request_id = str(evidence.get("request_id", ""))
        if not request_id or request_id in seen_request_ids:
            raise ValueError("evidence.request_id must be non-empty and unique")
        seen_request_ids.add(request_id)
        policy = record["feature_policy"]
        if not isinstance(policy, dict) or policy != {
            "request_time_only": True,
            "evidence_excluded_from_ml": True,
            "raw_payload_stored": False,
            "raw_cookie_stored": False,
        }:
            raise ValueError("record feature policy is not privacy-safe")
        request_features = record["request_features"]
        if any(name in request_features for name in ("uri", "query", "headers", "body", "cookie", "payload")):
            raise ValueError("raw request data is not permitted in request_features")
        _vector(record, feature_names)
        route_split_label[(route_id, str(split), str(label))] += 1

    dataset_routes = sorted({str(record["route"]["id"]) for record in records})
    for route_id in dataset_routes:
        if route_split_label[(route_id, "train", "normal")] < 1:
            raise ValueError(f"{route_id} has no train-normal records")
        if route_split_label[(route_id, "validation", "normal")] < 1:
            raise ValueError(f"{route_id} has no validation-normal records")
        if route_split_label[(route_id, "test", "normal")] < 1:
            raise ValueError(f"{route_id} has no test-normal records")
        if route_split_label[(route_id, "test", "attack")] < 1:
            raise ValueError(f"{route_id} has no held-out attack records")
    return feature_names


# Tóm tắt phân phối giá trị feature trong dataset.
def _summary(vectors: list[dict[str, float]], feature_names: tuple[str, ...]) -> dict[str, dict[str, float]]:
    return {
        name: {
            "min": min(vector[name] for vector in vectors),
            "max": max(vector[name] for vector in vectors),
            "mean": fmean(vector[name] for vector in vectors),
        }
        for name in feature_names
    }


# Tạo dataset đã xử lý và các split/manifest từ raw records.
def prepare(input_path: Path = DEFAULT_INPUT, output_dir: Path = DEFAULT_OUTPUT,
            manifest_dir: Path = DEFAULT_MANIFEST, registry_path: Path = DEFAULT_REGISTRY) -> dict[str, object]:
    input_path = Path(input_path).resolve()
    output_dir = Path(output_dir).resolve()
    manifest_dir = Path(manifest_dir).resolve()
    registry_path = Path(registry_path).resolve()
    registry = load_registry(registry_path)
    records = read_jsonl(input_path)
    feature_names = validate_records(records, registry)
    processed_rows = []
    partitions: dict[tuple[str, str], list[dict[str, float]]] = defaultdict(list)
    route_train: dict[str, list[dict[str, float]]] = defaultdict(list)
    counts = Counter()
    for record in records:
        route_id = str(record["route"]["id"])
        annotation = record["annotation"]
        vector = _vector(record, feature_names)
        split = str(annotation["split"])
        label = str(annotation["label"])
        partitions[(route_id, split)].append(vector)
        counts[(route_id, split, label)] += 1
        if split == "train" and label == "normal":
            route_train[route_id].append(vector)
        processed_rows.append({
            "schema_version": PROCESSED_SCHEMA,
            "record_id": record["record_id"],
            "group_id": record["collection"]["group_id"],
            "route": route_id,
            "split": split,
            "label": 0 if label == "normal" else 1,
            "label_name": label,
            "attack_type": annotation["attack_type"],
            "payload_variant": annotation["payload_variant"],
            "features": vector,
        })

    profiles = {
        route_id: {
            "schema_version": PROFILE_SCHEMA,
            "route": route_id,
            "train_normal_count": len(route_train[route_id]),
            "numeric_bounds": _summary(route_train[route_id], feature_names),
        }
        for route_id in sorted(route_train)
    }
    distributions = {
        route_id: {
            split: {
                "records": len(partitions[(route_id, split)]),
                "label_counts": {
                    label: counts[(route_id, split, label)]
                    for label in ("normal", "attack") if counts[(route_id, split, label)]
                },
                "feature_summary": _summary(partitions[(route_id, split)], feature_names),
            }
            for split in ("train", "validation", "test")
        }
        for route_id in sorted({str(record["route"]["id"]) for record in records})
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(parents=True, exist_ok=True)
    processed_path = output_dir / "feature_records.jsonl"
    profiles_path = output_dir / "route_normal_profiles.json"
    distribution_path = manifest_dir / "feature_distribution.json"
    manifest_path = manifest_dir / "prepare_manifest.json"
    write_jsonl(processed_path, processed_rows)
    profiles_path.write_text(json.dumps(profiles, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    distribution_path.write_text(json.dumps(distributions, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "wcp-prepare-manifest-v1",
        "input": str(input_path.relative_to(ROOT)).replace("\\", "/"),
        "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "records": len(processed_rows),
        "feature_count": len(feature_names),
        "feature_names": list(feature_names),
        "routes": sorted({str(record["route"]["id"]) for record in records}),
        "split_policy": "session-group split; train/validation normal-only; attacks held-out test only",
        "evidence_used_as_features": False,
        "outputs": {
            "feature_records": str(processed_path.relative_to(ROOT)).replace("\\", "/"),
            "route_normal_profiles": str(profiles_path.relative_to(ROOT)).replace("\\", "/"),
            "feature_distribution": str(distribution_path.relative_to(ROOT)).replace("\\", "/"),
        },
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


# Đọc tham số CLI và chạy pipeline dữ liệu/model của prepare_dataset.
def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare safe WCP request features for route-aware IF")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest-dir", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--route-registry", type=Path, default=DEFAULT_REGISTRY)
    args = parser.parse_args()
    manifest = prepare(args.input, args.output_dir, args.manifest_dir, args.route_registry)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
