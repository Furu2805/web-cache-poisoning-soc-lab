# Shadow runtime scope

This public snapshot keeps the existing `approved-shadow-only` registry decision from the local project configuration. The registry was cleaned by removing deprecated `blind_result` summary fields; route IDs, candidate IDs, model and threshold paths, feature profiles, route modes, and enforcement settings are unchanged. Its SHA-256 binding and evidence paths are refreshed for the files retained in this snapshot.

The decision allows candidate scoring in **shadow mode only**. All four routes remain `mode: shadow`, and `automatic_enforcement` is `false`. It is not a claim that the candidates are production-ready or that their detection quality has been independently validated. The demonstrations use synthetic local traffic; see [evaluation limits](EVALUATION.md).

Each route's `CHECKSUMS.sha256` covers the model, threshold, schema, feature profile, and profile guard loaded at runtime. The loader verifies those files and the registry binding before starting. Historical benchmark snapshots and their source datasets stay local-only because their run provenance is incomplete or inconsistent.
