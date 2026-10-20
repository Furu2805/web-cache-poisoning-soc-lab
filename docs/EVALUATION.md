# Evaluation note

All traffic evidence in this project comes from a local synthetic lab. No production ground truth or external out-of-distribution dataset is available.

The working directory contained historical audit snapshots with incompatible candidate-coverage and concurrent-latency conclusions. The snapshots are not tied to a common commit and reproducible run manifest, so this portfolio checkout does not publish aggregate performance or detector-quality numbers. Candidate score summaries, generated datasets, and the old result directory are intentionally excluded from Git. Runtime model packages remain so the shadow demo can start.

Before publishing a future metric, record the source commit, run ID, host CPU/RAM, Docker resource limits, concurrency, request/sample counts, dataset fingerprint, route-level confusion matrix, and whether the measurement is synthetic or externally sourced. Re-run the evaluation after changes to the candidate artifacts or request path.
