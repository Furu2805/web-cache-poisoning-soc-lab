# Full demo guide

The quick path takes 8 to 12 minutes. The complete walkthrough takes about 20 to 30 minutes and covers the CacheShield UI, legacy detector modes, all four Fusion scenarios, ML Shadow, SOC case handling, Grafana/Loki, and local SOC data utilities. It uses synthetic traffic and harmless markers; all services bind to localhost.

> **Lab boundary:** Grafana and demo secrets use fixed local credentials, and the SOC API has no authentication. Keep the stack on localhost. Candidate ML runs in shadow mode and does not make cache decisions.

The screenshots below come from local runs captured on 6 and 22 October 2026. They illustrate the evidence and UI; a fresh run will have different request IDs, case IDs, counts, and timestamps.

## System at a glance

The lab routes requests through Nginx. Port `8086` keeps the vulnerable teaching scenarios with the detector off; `8090` observes requests and sends candidate scoring to ML Shadow; `8091` enables the Baseline detector's configured cache action. Loki collects sanitized events, Grafana displays them, and triage correlates complete evidence by `request_id` into SOC cases and redacted reports.

![Lab architecture](architecture.svg)

![SOC monitoring dashboard](grafana-dashboard.png)

## 1. Start the lab

**Requirements:** Docker Desktop or Docker Engine with Compose v2, PowerShell 5.1 or later, and about 6 to 8 GiB available to Docker.

From the repository root:

```powershell
git lfs install
git lfs pull
docker compose up --build -d --wait
docker compose ps
```

Wait until the services show as running or healthy. Open the local SOC UI at <http://127.0.0.1:8080/soc/>, Grafana at <http://127.0.0.1:13000/>, and the Fusion storefront at <http://127.0.0.1:8090/>.

| Address | Purpose |
| --- | --- |
| `http://127.0.0.1:8080/` | Fusion storefront and legacy mode `none` |
| `http://127.0.0.1:8080/soc/` | CacheShield lab and SOC case workspace; choose **Cases & evidence** |
| `http://127.0.0.1:8081/` | Same UI; legacy rule mode |
| `http://127.0.0.1:8082/` | Same UI; legacy Isolation Forest mode |
| `http://127.0.0.1:8083/` | Same UI; legacy rule-or-ML hybrid mode |
| `http://127.0.0.1:8084/` | Same UI; legacy hardened cache mode |
| `http://127.0.0.1:8085/` | Same UI; legacy observe mode |
| `http://127.0.0.1:8086/` | Fusion scenarios, detector off (vulnerable teaching routes) |
| `http://127.0.0.1:8090/` | Fusion observe mode with Baseline assessment and ML Shadow |
| `http://127.0.0.1:8091/` | Fusion enforce mode with Baseline cache action |
| `http://127.0.0.1:13000/d/fusion-cache-security` | SOC dashboard |
| `http://127.0.0.1:13000/d/fusion-ml-shadow` | ML Shadow dashboard |
| `http://127.0.0.1:13100/ready` | Loki readiness |
| `http://127.0.0.1:8002/health` | Triage health |

Local Grafana credentials are `fusion-admin` / `fusion-local-admin`.

## Complete live walkthrough

### A. Show the CacheShield website and cache controls

Open <http://127.0.0.1:8080/>. The top chip shows the current legacy mode. In the website panel:

1. Click **Home**, **Product**, **Search**, and **News** to show the four cacheable backend endpoints. On Search, enter `LED` and submit.
2. Click **Tải lại dữ liệu** twice. The Cache Inspector should show `MISS` then `HIT` for the same URL; note the request ID and cache-key profile.
3. Switch **Client A** to **Client B**, then reload. The client header is not part of the cache key, so this demonstrates a shared response.
4. Turn on **X-Lab-Bypass: 1** and reload. The cache status should become `BYPASS`; turn it off afterward.
5. Click **Tạo cache key mới** and reload. The new `lab_session` query value gives the request a fresh cache key, so expect `MISS` followed by `HIT` on the next reload.

The four left navigation items open descriptions for XFH, unkeyed query, UTM cloaking, and fat GET. **Access the lab** opens that scenario on port `8086`; **Open patched variant** opens its fixed route. These route pages are for the Fusion scenario walkthrough below.

### B. Compare the six legacy detector/cache modes (optional, 5 minutes)

The legacy ports are separate Nginx configurations; changing the browser port changes the mode. `8080` is no detection, `8081` rule, `8082` Isolation Forest, `8083` rule-or-ML, `8084` hardened cache, and `8085` observe-only. The UI's chip confirms which one is open. This legacy observe mode is not the same as Fusion observe on `8090`: the latter emits the current Baseline assessment and ML Shadow evidence.

To compare behavior with the same harmless XFH marker, run this in PowerShell from the repository root. It clears the proxy cache first, uses a unique key, and prints response headers for an attacker-shaped request followed by a clean request on each mode port:

```powershell
.\reset-cache.ps1
$id = 'mode-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
foreach ($port in 8080..8085) {
  $uri = "http://127.0.0.1:$port/lab/xfh?id=$id"
  $attack = Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers @{ 'X-Forwarded-Host' = "poison-$id.test" }
  $clean = Invoke-WebRequest -UseBasicParsing -Uri $uri
  [pscustomobject]@{
    Port = $port
    Mode = $attack.Headers['X-Defense-Mode']
    AttackCache = $attack.Headers['X-Cache-Status']
    Decision = $attack.Headers['X-Decision']
    CleanCache = $clean.Headers['X-Cache-Status']
    CleanValue = $clean.Content
  }
}
```

Use the output to explain the differences, not as a benchmark: rule/hybrid can bypass a request with a Host/XFH mismatch, hardened mode removes trust in the client XFH and keys the full URI, and observe records without enforcing a cache action. ML output can depend on the loaded legacy model. The request contains only a `.test` host marker and stays on localhost.

### C. Prove the shared-cache effect and create a SOC case

Run the compact script in section 2. It resets the cache, sends a harmless `WCP_<token>` marker through the vulnerable Fusion query route at `8086`, and checks that a clean follow-up gets `HIT` with the marker. It then sends an XFH anomaly through `8090` and waits for automatic case creation after the evidence is complete.

Read out `MISS -> HIT`, `MarkerReachedVictim`, the request ID, case ID, and evidence sources. This is the clearest end-to-end proof to present before opening dashboards.

### D. Replay all four current Fusion scenarios

Run the four `run_stage15.ps1` commands in section 4. They exercise XFH, query, UTM cloaking, and fat GET through `8091=enforce`, then check the clean-client result and evidence delivery. For each run, open its `results/stage15/<run-id>/stage15_e2e_summary.json` and read the mode, Baseline classification, cache status, clean-client assertion, and `passed` field. The runner handles the GET-with-body case that a browser's Fetch API cannot send reliably.

For a patched-route comparison, use **Open patched variant** from the scenario description, or add `/fixed/` to the matching route under `8086`; compare the response and `X-Lab-Patched` header. The live demo uses text markers and does not need an external host or script.

### E. Work the SOC case like an analyst

At <http://127.0.0.1:8080/soc/>, select **Cases & evidence**. Refresh if the new case has not appeared yet. Use the search box for its case/request ID, or filter by severity, status, route, and time. Open the row and walk through:

1. The campaign request count, route, severity, status, and first/last-seen timestamps.
2. The evidence timeline grouped by source: Nginx, Baseline detector, ML Shadow, and triage. Point out that all sources are correlated by request ID and that ML remains advisory.
3. Set status to `investigating`, assign `demo-analyst`, choose an analyst outcome, and add a short note that refers to the observed cache status and clean-client result. Click **Save case updates**; reopen **Audit trail** to show the recorded changes.
4. Select a mitigation recommendation and keep its decision at `pending_review` for the first save. To show the review gate, choose `approved` or `rejected` only with a reviewer name such as `demo-reviewer`. This records an audit decision; it does not edit Nginx or change the cache. Any real cache change must be applied and verified manually under the runbook.
5. Run the same Stage 15 scenario again within 15 minutes while the case remains active. If it has the same scenario, route, and technique fingerprint, the correlator should link the new request into that case; show the updated request count and `request-linked` audit event.

The screenshots show the analyst queue and a selected case with its evidence timeline:

![SOC analyst queue with a selected case](demo-assets/soc-case-queue.png)

![SOC case detail and source-labelled evidence timeline](demo-assets/soc-case-detail.png)

The screenshots are from example captures. Their request and case IDs, route, and counts may differ from the current run. During a live demo, search using the `CaseId` and `RequestId` printed by `demo-quick.ps1` so the terminal output and case detail refer to the current evidence.

Saving notes, labels, decisions, or statuses writes local case/report and audit data under `data/`. Use a fresh local lab or a disposable case if you want the demo to leave existing analyst data untouched. Dashboard MTTA/MTTR and false-positive metrics can stay `N/A` until there are enough corresponding analyst actions and resolved/labeled cases.

### F. Show monitoring and model evaluation

Open the Grafana SOC dashboard and the ML Shadow dashboard from the address table. Use a request ID from the demo to search the four LogQL streams in section 5. Show Nginx cache state, Baseline decision, asynchronous Shadow completion, and triage/incident events. Explain that `8090` observes and `8091` enforces only the Baseline configured cache action; the ML candidate never controls Nginx.

Use the existing route evaluation table in section 6 to discuss precision, recall, F1, FPR, support, and the Query-route ablation. These are frozen synthetic local results, not production estimates. For a new reproducible evaluation, follow `ml-detector/README.md`; do not overwrite the checked-in report during a live demo.

### G. Close the demo and show local data utilities (optional)

Create a checksum-manifested backup of cases/audit streams, then preview retention eligibility without deleting anything:

```powershell
python scripts/backup_soc_data.py
python scripts/maintain_soc_data.py
```

The second command is dry-run by default. Do not add `--apply` during the demo: apply archives then removes eligible old resolved/false-positive case report files. Stop the stack with `docker compose down`; this keeps named volumes. Avoid `docker compose down -v` if you want to retain Grafana and MongoDB state.

## 2. Prove the cache effect and automatic SOC case

Run the compact demo:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\demo-quick.ps1
```

The script resets the Nginx cache, puts a harmless marker into the vulnerable query route, and sends a clean request with the same cache key. It then sends an X-Forwarded-Host anomaly through observe mode and waits for the SOC correlator to create a case after the Nginx, Baseline, and ML Shadow evidence arrives.

Look for output fields like `PoisonCache`, `CleanVictimCache`, `MarkerReachedVictim`, `RequestId`, `CaseId`, and `EvidenceSources`. The expected cache proof is `MISS` (or `EXPIRED`) followed by `HIT`, with the marker present in the clean response. In **Cases & evidence**, open the matching case and inspect its source-labelled timeline.

This marker is intentionally harmless. It demonstrates shared-cache behavior without loading an external script or contacting an external host.

## 3. Send normal traffic through observe mode

The following requests exercise all four routes without supplying an attack input. Observe mode returns the application response while the Baseline and ML Shadow record their assessments.

```powershell
$demo = 'cv-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
$urls = @(
  "http://127.0.0.1:8090/labs/query/?cb=$demo&page=1&view=grid",
  "http://127.0.0.1:8090/labs/xfh/shop?cb=$demo&category=electronics",
  "http://127.0.0.1:8090/labs/utm/js/geolocate.js?callback=setCountryCookie&locale=vi&cb=$demo",
  "http://127.0.0.1:8090/labs/fatget/js/geolocate.js?callback=setCountryCookie&locale=vi&cb=$demo"
)
$urls | ForEach-Object {
  $r = Invoke-WebRequest -UseBasicParsing -Uri $_
  [pscustomobject]@{
    Status = $r.StatusCode
    RequestId = $r.Headers['X-Request-ID']
    Cache = $r.Headers['X-Cache-Status']
    DetectorMode = $r.Headers['X-Fusion-Detector-Mode']
    Baseline = $r.Headers['X-Fusion-Detector-Decision']
  }
}
```

Use the `RequestId` to find the corresponding events in Grafana Explore. Candidate results can arrive asynchronously; the request response does not wait for ML Shadow to finish.

The report captured an XFH request in observe mode. Nginx returned `MISS`, while the detector labeled it anomalous and recommended `bypass-no-cache`; observe mode records that recommendation without enforcing it.

![XFH request and response in observe mode](demo-assets/xfh-observe.png)

## 4. Replay all four scenarios through the enforced path

The Stage 15 runner sends one controlled scenario through port `8091`, checks the clean follow-up request, waits for Loki evidence, and creates a redacted incident report. It does not change the default vulnerable lab mode on port `8086`.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_stage15.ps1 -Scenario xfh
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_stage15.ps1 -Scenario query
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_stage15.ps1 -Scenario utm
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_stage15.ps1 -Scenario fatget
```

Each run prints a sanitized summary and writes `results/stage15/<run-id>/stage15_e2e_summary.json`. The `results/` directory is local-only and ignored by Git. Check these fields in each summary:

- `attacker_request.detector_mode` is `enforce`, and the Baseline classifies the request as an anomaly.
- `attacker_request.cache_status` is `BYPASS`; the suspicious response is not stored as a shared cache object.
- `clean_client_request.cache_status` is `MISS`, and `clean_client_not_poisoned` is true.
- Loki received the Nginx, detector, triage, and incident events; `incident_report.raw_values_available` is false.
- `passed` is true when all assertions in the local replay pass.

This enforced replay demonstrates the Baseline cache action. ML candidates remain asynchronous and have no cache authority. The vulnerable proof in the previous section is a separate run on port `8086`.

![XFH response in enforce mode with cache status BYPASS](demo-assets/xfh-enforce.png)

## 5. Follow evidence into Grafana and the SOC

Use one `RequestId` from the current `demo-quick.ps1` output to follow the activity. The screenshots in this section include several saved example runs: the Explore captures use a Fat GET request, while the SOC case capture shows a UTM route. Their IDs are not expected to match each other or a new run. For a live trace, use the current request ID in every Explore query and the current case ID in the SOC UI.

### SOC dashboard

Open the [Fusion Web Cache Security Monitoring dashboard](http://127.0.0.1:13000/d/fusion-cache-security), set the time range to **Last 1 hour**, and refresh. Start with request volume, anomaly events, and cache HIT/MISS/BYPASS. Then show **Latest inspected requests** and the panels for automatically created cases, campaign grouping, and analyst updates.

![SOC dashboard request, anomaly, and cache overview](demo-assets/soc-dashboard-overview.png)

![SOC dashboard suspicious routes and cache distribution](demo-assets/soc-dashboard-suspicious-uris.png)

![Latest inspected requests and automatic case metrics](demo-assets/soc-dashboard-latest-requests-cases.png)

The dashboard values reflect retained lab events in the selected time range. In the screenshots, some totals are large, **Normal requests** and **Header-related anomaly signals** show `No data`, and the scenario panel shows 100%. Describe these as the current lab dashboard view; do not present them as results from one request or as production detection rates. `No data` means the query returned no series in that view, not necessarily a measured zero.

### ML Shadow dashboard

Open the [Fusion Route-aware ML Shadow Monitoring dashboard](http://127.0.0.1:13000/d/fusion-ml-shadow). Show **Candidate coverage by route**, **IF / profile / final anomaly rate by route**, then **Queue depth / queue lag / batch size** and the inference latency panels.

![ML Shadow candidate coverage and route anomaly panels](demo-assets/ml-shadow-route-coverage.png)

![ML Shadow queue and latency panels](demo-assets/ml-shadow-queue-latency.png)

ML Shadow is asynchronous and advisory. In the saved Fat GET trace, the candidate result differs from the Baseline result; triage preserves both assessments. Use the panels to explain coverage and pipeline health, not to claim a production benchmark. A `No data` panel is not evidence of a zero error or fallback rate.

### Follow a request in Explore

In Grafana, select **Explore** and the **Fusion Loki** data source. Search using the request ID from the current demo output. These LogQL queries isolate the four evidence sources:

```logql
{job="fusion-nginx"} | json | request_id="<request-id>"
{job="fusion-detector"} | json | request_id="<request-id>"
{job="fusion-ml-shadow"} | json | request_id="<request-id>" | event_type="shadow_completed"
{job="fusion-triage"} | json | request_id="<request-id>"
{job="fusion-case-pipeline"} | json | request_id="<request-id>"
{job="fusion-case-audit"} | json
```

If using the visual query builder, choose the matching `job` label and filter the log line by the request ID. The captures below follow the same example Fat GET request through Nginx, Baseline, ML Shadow acceptance/completion, and triage.

![Explore query filtered to the example Nginx request](demo-assets/explore-nginx-query.png)

![Nginx cache and request evidence](demo-assets/explore-nginx-event.png)

![Baseline detector classification and action](demo-assets/explore-detector-event.png)

![Baseline indicator fields](demo-assets/explore-detector-indicators.png)

![ML Shadow completed inference event](demo-assets/explore-shadow-completed.png)

![ML Shadow accepted event showing asynchronous queueing](demo-assets/explore-shadow-accepted.png)

![Triage event linking the request to a suspected technique](demo-assets/explore-triage-event.png)

![Triage technique and local rules-engine details](demo-assets/explore-triage-details.png)

Read the events in order: Nginx records cache status, Baseline records its decision and recommendation, ML Shadow records queueing and later completion, and triage creates or updates a case after evidence is complete. Compare the candidate result with Baseline; ML Shadow does not control Nginx.

### Alert rules

Open **Alerting → Alert rules** and find the **Fusion ML shadow alerts** group. The captured list shows five provisioned rules: model or schema load failure, anomaly rate elevated, queue overflow, candidate coverage low, and queue lag high.

![Provisioned Fusion ML Shadow alert rules](demo-assets/grafana-alert-rules.png)

At capture time, all five were `Normal`. Open a rule and its **State history** only if you want to show prior transitions. The following history screenshots include older `Alerting`, `Pending`, `NoData`, and `Error` states; they are historical and do not mean the rules are firing now.

![Model or schema load-failure rule state history](demo-assets/alert-history-registry-schema.png)

![Anomaly-rate rule state history](demo-assets/alert-history-anomaly-rate.png)

![Candidate-coverage rule state history](demo-assets/alert-history-candidate-coverage.png)

![Queue-lag rule state history](demo-assets/alert-history-queue-lag.png)

The report's Loki/Grafana smoke summary records the provisioned panels, checked LogQL queries, alert rules, and queue-depth event:

![Grafana and Loki smoke-test summary from the report](demo-assets/grafana-loki-smoke.png)

These report captures show how one request ID links the Nginx event to the asynchronous ML Shadow completion:

![Nginx access evidence in Loki](demo-assets/loki-nginx-evidence.png)

![Accepted and completed ML Shadow events in Loki](demo-assets/ml-shadow-evidence.png)

The report also captured the direct triage and incident-report API responses. The walkthrough creates and reviews cases in the SOC UI; these images show the underlying redacted evidence endpoints.

![Evidence-based triage response](demo-assets/triage-response.png)

![Redacted incident report created from a request ID](demo-assets/incident-created.png)

![Incident report with candidate assessment and cache evidence](demo-assets/incident-evidence.png)

## 6. Explain the detector result

The current evaluation snapshot uses 1,000 normal and 1,000 attack samples per route in synthetic local blind sets. The route metrics below are for the Isolation Forest candidate in that snapshot. The run ID is `20261020T054343Z-de3535fa`; the source commit and data/model fingerprints are recorded in the [full evaluation report](../ml-detector/DETECTOR_EVALUATION.md).

| Route | Precision | Recall | F1 | FPR | What the ablation showed |
| --- | ---: | ---: | ---: | ---: | --- |
| XFH | 99.21% | 100% | 99.60% | 0.8% | No additional true positives over the profile guard |
| Query | 99.11% | 100% | 99.55% | 0.9% | IF found 200 attack samples missed by the profile guard, with 9 additional false positives |
| UTM cloaking | 99.50% | 100% | 99.75% | 0.5% | No additional true positives over the profile guard |
| Fat GET | 98.04% | 100% | 99.01% | 2.0% | No additional true positives; FPR is at the evaluation gate |

The strongest ML contribution in this snapshot is the Query route. On the other routes, the profile guard already detects the blind attacks and IF adds false positives. These figures describe frozen synthetic lab distributions; they do not estimate production detection rates. See the [dataset card](../ml-detector/DATASET_CARD.md) for the data-generation and split details, and the [evaluation note](EVALUATION.md) for limits on performance comparisons.

![IF-only confusion matrices across the four route blind sets](demo-assets/if-blind-confusion-matrices.png)

![Query route ablation showing the additional 200 attack samples detected by IF](demo-assets/query-if-ablation.png)

## 7. Optional SOC replay metrics

To calculate alert-to-case and evidence completeness from sanitized local events, run the replay evaluator with event files from your run:

```powershell
python scripts/evaluate_soc_replay.py `
  --events data/events/fusion-nginx-access.jsonl `
  --events data/events/detector-events.jsonl `
  --events data/events/ml-shadow-events.jsonl `
  --run-id replay-001 `
  --machine "CPU and RAM profile" `
  --concurrency 1 `
  --output data/reports/replay-001.json
```

The evaluator records the current Git commit when available and hashes each input. Add `--labels labels.json` for analyst-labelled false-positive rate and `--actions data/events/case-audit-events.jsonl` for MTTA/MTTR. Unlabelled cases remain `N/A`; do not treat an unreviewed case as ground truth.

## 8. Stop the lab

```powershell
docker compose down
```

This stops containers and keeps named volumes. Avoid `docker compose down -v` if you want to preserve local Grafana and MongoDB state. The quick demo resets the Nginx cache on its next run.

## Demo limits

- Traffic and detector evaluation use synthetic local scenarios, not production traffic or production labels.
- The blind sets are generated within this project; they are not an independent external OOD evaluation.
- Port `8090` is observe mode. Port `8091` uses the Baseline's configured enforcement; ML Shadow stays non-authoritative.
- The SOC API is unauthenticated, the local credentials are fixed demo values, and the stack must not be exposed to the Internet.
- Historical performance runs used different cache states and configurations. No latency or throughput comparison is presented here as a controlled overhead measurement.
