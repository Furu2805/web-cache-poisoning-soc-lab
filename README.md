# Web Cache Poisoning Detection & Monitoring Lab

A Dockerized research lab for reproducing web cache poisoning (WCP) and observing a route-aware detector in shadow mode. It combines an Nginx shared cache, a FastAPI baseline detector, isolated ML shadow scoring, Loki/Grafana, and evidence-based incident triage.

> **Scope:** local educational lab. The SOC API is unauthenticated and intended for loopback use only. Candidate ML does not enforce cache actions. Synthetic traffic results do not establish production performance or detection quality.

> **Credential boundary:** Compose contains fixed demo credentials and secrets. Keep the stack on localhost; do not reuse those values or expose the unauthenticated SOC API. An external deployment needs managed secrets, TLS and authentication/RBAC, durable storage, retention, and tested backups.

![System architecture](docs/architecture.svg)

![Grafana SOC dashboard](docs/grafana-dashboard.png)

## What it demonstrates

- Four local WCP variants: unkeyed header, query, UTM parameter cloaking, and fat GET.
- A safe cache proof: a harmless marker is cached on `MISS` and served to a clean request on `HIT`.
- Route-aware candidate scoring with per-route schemas and artifacts, bounded asynchronous delivery, and checksum validation.
- Automatic SOC cases from complete anomaly evidence, campaign grouping, analyst workflow, and a source-labelled timeline.
- Request correlation through Nginx, baseline detector, ML shadow, Loki/Grafana, and redacted triage.

## Run locally

**Requirements:** Docker Desktop/Engine with Compose v2, PowerShell 5.1+, and about 6 to 8 GiB available to Docker. The published service ports bind to localhost.

```powershell
git lfs install
git clone https://github.com/Furu2805/web-cache-poisoning-soc-lab.git
cd web-cache-poisoning-soc-lab
git lfs pull
docker compose up --build -d --wait
```

For an existing checkout, start at `docker compose up --build -d --wait`.

## Quick demo

After the stack starts, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\demo-quick.ps1
```

It resets the cache, verifies the harmless `MISS -> HIT` marker flow, sends one XFH anomaly through observe mode, then waits for the SOC correlator to create a case from the complete evidence. Open the lab at <http://127.0.0.1:8080/> and select **Cases & evidence**, or open Grafana at <http://127.0.0.1:13000/d/fusion-cache-security>. For the four-route walkthrough and analyst runbook, see the [full demo guide](docs/FULL_DEMO_GUIDE.md).

| Local address | Purpose |
| --- | --- |
| `http://127.0.0.1:8086/` | Vulnerable cache lab, detector off |
| `http://127.0.0.1:8090/` | Observe mode with ML shadow |
| `http://127.0.0.1:13000/` | Grafana (`fusion-admin` / `fusion-local-admin`) |
| `http://127.0.0.1:13100/ready` | Loki readiness |
| `http://127.0.0.1:8002/health` | Triage health |
| `http://127.0.0.1:8080/` | Local SOC case queue |

## Evaluation and limitations

The demonstrations use synthetic local traffic. There is no production ground truth or external out-of-distribution validation. Historical benchmark snapshots disagree on candidate coverage and concurrent latency, so this README publishes no aggregate performance or recall claim. Re-run and tie any future number to a commit, run ID, machine configuration, concurrency, and sample counts before citing it.

## Source attribution

The lab includes the Fusion Electronics storefront, adapted from [MERN-Stack-Ecommerce-App](https://github.com/hoangsonww/MERN-Stack-Ecommerce-App). Its MIT license and copyright notice are retained in [`vendor/fusion-electronics/LICENSE`](vendor/fusion-electronics/LICENSE); see [third-party notices](THIRD_PARTY_NOTICES.md).

## Project context and contribution

This is a group project built with AI assistance. I used AI during implementation; this portfolio copy does not claim sole authorship of any subsystem.

## More detail

- [Full demo guide](docs/FULL_DEMO_GUIDE.md)
- [Evaluation note](docs/EVALUATION.md)
- [Source references](docs/SOURCES.md)
