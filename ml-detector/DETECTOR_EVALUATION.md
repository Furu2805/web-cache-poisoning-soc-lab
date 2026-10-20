# Route detector evaluation

- Run ID: `20261020T054343Z-de3535fa`
- Created (UTC): `2026-10-20T05:43:43+00:00`
- Source commit: `5d4c072516c55ca7bb242a0a0b05b393d4ef75a6`; working tree dirty: `true`
- Evaluation script SHA-256: `c7877d97c5511482041ce0b2b11e18eee21481935c6af78dce8c8b1d94c46f4d`
- Runtime: Python `3.12.7`, scikit-learn `1.8.0`, CPU count `12`, physical RAM `34065440768` bytes
- Scoring: `offline CPU; frozen candidates; no request concurrency`

> All rows below are synthetic local lab traffic. The independent set uses separately generated variants; it is a novelty holdout, not evidence of production or external OOD performance.

## Held-out metrics by route

| Route | Split | Detector | Precision | Recall | F1 | FPR | Support N/A |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| xfh | development test | rule | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| xfh | development test | profile | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| xfh | development test | if | 0.9881 | 1.0000 | 0.9940 | 0.0120 | 1000/1000 |
| xfh | development test | hybrid | 0.9881 | 1.0000 | 0.9940 | 0.0120 | 1000/1000 |
| xfh | independent blind | rule | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| xfh | independent blind | profile | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| xfh | independent blind | if | 0.9921 | 1.0000 | 0.9960 | 0.0080 | 1000/1000 |
| xfh | independent blind | hybrid | 0.9921 | 1.0000 | 0.9960 | 0.0080 | 1000/1000 |
| query | development test | rule | 1.0000 | 0.6000 | 0.7500 | 0.0000 | 1000/1000 |
| query | development test | profile | 1.0000 | 0.8000 | 0.8889 | 0.0000 | 1000/1000 |
| query | development test | if | 0.9872 | 1.0000 | 0.9935 | 0.0130 | 1000/1000 |
| query | development test | hybrid | 0.9872 | 1.0000 | 0.9935 | 0.0130 | 1000/1000 |
| query | independent blind | rule | 1.0000 | 0.6000 | 0.7500 | 0.0000 | 1000/1000 |
| query | independent blind | profile | 1.0000 | 0.8000 | 0.8889 | 0.0000 | 1000/1000 |
| query | independent blind | if | 0.9911 | 1.0000 | 0.9955 | 0.0090 | 1000/1000 |
| query | independent blind | hybrid | 0.9911 | 1.0000 | 0.9955 | 0.0090 | 1000/1000 |
| utm | development test | rule | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| utm | development test | profile | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| utm | development test | if | 0.9960 | 1.0000 | 0.9980 | 0.0040 | 1000/1000 |
| utm | development test | hybrid | 0.9960 | 1.0000 | 0.9980 | 0.0040 | 1000/1000 |
| utm | independent blind | rule | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| utm | independent blind | profile | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| utm | independent blind | if | 0.9950 | 1.0000 | 0.9975 | 0.0050 | 1000/1000 |
| utm | independent blind | hybrid | 0.9950 | 1.0000 | 0.9975 | 0.0050 | 1000/1000 |
| fatget | development test | rule | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| fatget | development test | profile | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| fatget | development test | if | 0.9960 | 1.0000 | 0.9980 | 0.0040 | 1000/1000 |
| fatget | development test | hybrid | 0.9960 | 1.0000 | 0.9980 | 0.0040 | 1000/1000 |
| fatget | independent blind | rule | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| fatget | independent blind | profile | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1000/1000 |
| fatget | independent blind | if | 0.9804 | 1.0000 | 0.9901 | 0.0200 | 1000/1000 |
| fatget | independent blind | hybrid | 0.9804 | 1.0000 | 0.9901 | 0.0200 | 1000/1000 |

`Support N/A` is the count of normal/attack samples. The rule baseline is intentionally specific to each lab primitive; repeated rule/profile values on XFH and Fat GET are expected because their packaged profile guard is the same explicit primitive.

## Isolation Forest ablation

| Route | Split | Component | Precision | Recall | F1 | FPR | Support N/A |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| xfh | development test | relationship_if | 0.9881 | 1.0000 | 0.9940 | 0.0120 | 1000/1000 |
| xfh | independent blind | relationship_if | 0.9921 | 1.0000 | 0.9960 | 0.0080 | 1000/1000 |
| query | development test | structural_if | 0.0000 | 0.0000 | 0.0000 | 0.0020 | 1000/1000 |
| query | development test | relationship_if | 0.9891 | 1.0000 | 0.9945 | 0.0110 | 1000/1000 |
| query | independent blind | structural_if | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1000/1000 |
| query | independent blind | relationship_if | 0.9911 | 1.0000 | 0.9955 | 0.0090 | 1000/1000 |
| utm | development test | structural_if | 0.0000 | 0.0000 | 0.0000 | 0.0030 | 1000/1000 |
| utm | development test | relationship_if | 0.9990 | 1.0000 | 0.9995 | 0.0010 | 1000/1000 |
| utm | independent blind | structural_if | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1000/1000 |
| utm | independent blind | relationship_if | 0.9950 | 1.0000 | 0.9975 | 0.0050 | 1000/1000 |
| fatget | development test | relationship_if | 0.9960 | 1.0000 | 0.9980 | 0.0040 | 1000/1000 |
| fatget | independent blind | relationship_if | 0.9804 | 1.0000 | 0.9901 | 0.0200 | 1000/1000 |

## IF contribution relative to profile

| Route | Split | IF-only TP | IF-only FP | Profile-only TP | Profile-only FP | Overlap TP | Overlap FP |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| xfh | development test | 0 | 12 | 0 | 0 | 1000 | 0 |
| xfh | independent blind | 0 | 8 | 0 | 0 | 1000 | 0 |
| query | development test | 200 | 13 | 0 | 0 | 800 | 0 |
| query | independent blind | 200 | 9 | 0 | 0 | 800 | 0 |
| utm | development test | 0 | 4 | 0 | 0 | 1000 | 0 |
| utm | independent blind | 0 | 5 | 0 | 0 | 1000 | 0 |
| fatget | development test | 0 | 4 | 0 | 0 | 1000 | 0 |
| fatget | independent blind | 0 | 20 | 0 | 0 | 1000 | 0 |

## Provenance and limits

- `xfh` (`xfh-phase1-v3-relation-distance`): development seed `20270817`, train normal `8000`, validation normal `2000`, test normal/attack `1000/1000`; development data SHA-256 `50a7972367d80897d33d1b75f3328883387c231ac1064b6bdafe2917d3a6099d`, blind data SHA-256 `3b5ef74b901ed6afa2540b246bba726269b2273a26842d604969d0217b9a80b8`, candidate SHA-256 `6264cc95c8df4afc7c9a0b9654b6ec3a08d9c456089b72c8cb750667249e9d78`.
- `query` (`query-phase2-v8-full-sample-novelty`): development seed `20270629`, train normal `8000`, validation normal `2000`, test normal/attack `1000/1000`; development data SHA-256 `d2e025bed8cb5d0f965ee8bfa470db49daac20cea970c9b376011317f0d74b45`, blind data SHA-256 `a69d3fbb34a11fa73d58f0762704888d14500aa5014c2f5113cc0fa545068b3e`, candidate SHA-256 `6c1f28bb66444b650637d14cfc33a1d7744e853c499d63883b8bea5cab5b72b9`.
- `utm` (`utm-phase3-dual-if-novelty`): development seed `20261005`, train normal `5000`, validation normal `1000`, test normal/attack `1000/1000`; development data SHA-256 `8408f556a3f0b57347e49bca75e075aff83ab0cea336e0e5758b15d7b91155dc`, blind data SHA-256 `fbc480c2a5aa300a69c0cba698235f701410e25b95f353de2c0d90aae6463978`, candidate SHA-256 `6b28c3b64e94595d8a78bbcee80416c3ee59dbf3ac3741c284a24d43a21f0870`.
- `fatget` (`fatget-phase4-v2-body-relation`): development seed `20270921`, train normal `8000`, validation normal `2000`, test normal/attack `1000/1000`; development data SHA-256 `59da25d573f7c67f2267ba716e5d7817d2c3d2eb6472cd5231323d670fcad3fe`, blind data SHA-256 `68afb66a9e0c7309fafd599fd55b120d6f8c02d57f6151541da2f801d49b6c2e`, candidate SHA-256 `25ac3e82d9f78f3c542f61beaa3f021e38fb58d83492ff3d8f54d4036af927a9`.

Raw request data and generated feature sets are excluded from Git. Recreate them against the local lab with the replay command in [the dataset card](DATASET_CARD.md), then rerun the evaluator. Fresh collection produces a new run ID and dataset fingerprints; do not cite a metric without those identifiers.

Synthetic traffic is useful for checking the known lab primitives and pipeline behavior. It does not model the full request mix, attacker behavior, proxy variation, or analyst labels seen in production. No production effectiveness claim is made.
