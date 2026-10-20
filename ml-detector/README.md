# Route aware ML shadow candidates

This workspace trains and evaluates per route anomaly candidates for the lab. The active registry in [`config/model_registry.json`](config/model_registry.json) selects the model, threshold, feature schema, and normal profile for each route.

Candidates run in shadow mode. They do not choose cache behavior or block requests. The checked in model packages contain only runtime artifacts; historical metric reports and generated datasets stay local because the available snapshots do not share a complete reproducible run record.

Evaluation scripts live in `src/`. To publish a detector metric, first rerun the evaluation and record the source commit, run ID, host resources, concurrency, sample counts, and dataset fingerprint. See the project [evaluation note](../docs/EVALUATION.md).
