# Evaluation note

The current route-level detector run is recorded in [the detector evaluation report](../ml-detector/DETECTOR_EVALUATION.md). It includes per-route precision, recall, F1, false-positive rate (FPR), normal/attack support, detector comparisons, and Isolation Forest component ablation. Its run ID, source commit, host details, sample counts, and dataset/candidate SHA-256 fingerprints are in the report.

All measurements use synthetic traffic from the local Fusion lab. The separately collected blind sets are synthetic novelty holdouts from that lab; they are not externally sourced production OOD datasets. Do not present these results as production effectiveness or production false-positive rates.

The earlier audit snapshots use incompatible candidate coverage and run configurations. They are not combined into an aggregate metric. Recreate data and re-score the frozen candidates with the command and instructions in the [dataset card](../ml-detector/DATASET_CARD.md). Fresh collection creates new dataset fingerprints and a new run ID; keep the generated JSON report with any metric citation.

Generated datasets and raw request material are excluded from Git. Model packages in `ml-detector/artifacts/candidates/` remain frozen, candidate-only artifacts; evaluation does not promote them or change runtime cache behavior.
