# Fusion traffic dataset

Pipeline này chỉ sinh traffic cho bốn route Fusion tại `127.0.0.1:8086`:
`xfh`, `query`, `utm` và `fatget`. Prototype cũ nằm riêng ở
[`../traffic_legacy`](../traffic_legacy).

Chạy sau khi Docker stack hoạt động:

```powershell
python -m traffic.fusion_collect
```

Chuẩn hóa dataset và tạo feature request-only cho Giai đoạn 5:

```powershell
python -m traffic.fusion_features
```

Kết quả được ghi đè có chủ đích tại `data/fusion/raw/fusion_dataset.jsonl` và
manifest tại `data/fusion/manifests/fusion_dataset_manifest.json`. Mặc định có
50 normal + 50 attack cho mỗi lab, tổng cộng 400 request. Normal traffic có
cookie vô hại, query hợp lệ đa dạng và 20% `HEAD`; mỗi family attack có ít nhất
hai biến thể. Không dùng
`observation.cache_status`, `observation.cache_key` hoặc response metadata làm
feature detector vì các trường đó chỉ tồn tại sau khi cache đã xử lý request.
Mỗi record lưu thêm `request_id` do Nginx sinh và trả qua `X-Request-ID`, để
join với Nginx/ML/Loki log ở các giai đoạn sau.

Lệnh feature tạo `data/fusion/processed/ml_dataset.jsonl`,
`features.csv`, `feature_profile.json` và `feature_manifest.json`.
Profile header hiếm chỉ được fit từ normal-train. Dataset model-facing không
chứa `observation`/cache response và không dùng `request_id` làm feature.

Sau khi chuẩn hóa, chạy baseline normal-only theo thứ tự:

```powershell
python -m ml.tune
python -m ml.train
python -m ml.evaluate
```

`ml.train` chỉ fit trên Fusion `train` normal và chọn threshold chỉ từ
`validation` normal. `ml.evaluate` kiểm tra SHA-256 dataset đã ghi trong model;
vì vậy cần train lại sau khi thu hoặc chuẩn hóa dataset mới. Kết quả baseline
và giới hạn của nó được ghi tại `docs/STAGE6_ML_DETECTOR_FUSION.md`.

Mặc định của các lệnh `ml.*` hiện trỏ tới collection xác nhận detector 800
record trong `data/fusion/processed_detector_v2/`. Tiêu chí, kết quả hold-out
và giới hạn diễn giải nằm tại `docs/STAGE6_DETECTOR_CRITERIA_FUSION.md`.

## Candidate Isolation Forest có đóng góp đo được

Nếu cần kiểm tra liệu Isolation Forest có bắt thêm anomaly ngoài
normal-profile hay không, dùng candidate workflow thay vì ghi đè model runtime:

```powershell
.\scripts\run_iforest_contribution.ps1
```

Workflow sinh normal traffic đa dạng nhưng hợp lệ, giữ attack ở held-out test và
ghi `iforest_contribution.json`. Candidate chỉ được promote khi có IF-only true
positive và không có IF-only false positive. Xem
[`../docs/IFOREST_CONTRIBUTION_RETRAIN.md`](../docs/IFOREST_CONTRIBUTION_RETRAIN.md)
để biết giới hạn và thao tác promote.

Nhãn:

- `normal`: request hợp lệ không chứa điều kiện khai thác.
- `attack`: request theo đúng bốn primitive local: `xfh-unkeyed-header`,
  `query-unkeyed-parameter`, `utm-parameter-cloaking`, `fat-get-body`.

## Giai đoạn 14: benchmark hiệu năng

Benchmark Fusion hiện hành không dùng artefact `traffic_legacy/`. Chạy từ
PowerShell sau khi stack Docker hoạt động:

```powershell
.\scripts\run_stage14.ps1
```

Nó đo `off`/`observe`/`enforce` trên ba cổng localhost operator-owned, tách
cold/warm, ghi p50/p95/p99, cache hit ratio, `X-Detector-Ms`, volume JSONL và
delivery Loki/Grafana vào `results/stage14/<run-id>/`. Xem giới hạn và cách đọc
bảng tại `docs/STAGE14_PERFORMANCE_FUSION.md`.

## Giai đoạn 15: demo end-to-end phòng thủ

Chạy một request anomaly và một request sạch cùng cache key qua cổng
`8091=enforce`, sau đó xác minh Loki, triage, Incident Report và Grafana:

```powershell
.\scripts\run_stage15.ps1
```

Kết quả sanitize nằm tại `results/stage15/<run-id>/stage15_e2e_summary.json`.
Cổng học/Burp `8086` không bị thay đổi và vẫn `off`. Xem
`docs/STAGE15_E2E_DEMO_FUSION.md` để có request Burp tương đương và giới hạn
diễn giải.
