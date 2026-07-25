# Phase 4 observation run

## Evidence rule

An observation passes only when the database contains continuous, trustworthy data for the whole
claimed period. Elapsed wall-clock time may not be inferred from row count. Missing intervals,
clock skew, restarts, deployment changes, and disabled hosts must be recorded.

At the 2026-07-24 baseline:

- Guardian metrics covered about 3.5 calendar days, not seven verified continuous days;
- service-check results covered about two calendar days;
- only two Guardian Agents were active;
- Komari data had been recently migrated and was not a seven-day comparison baseline.

Therefore 24-hour continuity still needs a formal gap calculation and seven-day observation is
**PENDING**.

## Run identity

Create one immutable run record containing:

- run ID and UTC start/end;
- reviewed deployment commit and release;
- Controller, Web, Database, Gateway, and Agent versions;
- enabled-host and active-Agent inventory;
- expected heartbeat/check sampling intervals;
- time-sync status;
- notification and recovery gate state;
- hashes or object identifiers for generated evidence.

Do not include credentials, tokens, private addresses, or customer data.

## Hourly checkpoint

Record:

1. Controller/Web/Gateway/Database health and restart counts;
2. enabled, fresh, stale, disabled, unregistered, and pending-enrollment host counts;
3. newest and oldest sample timestamps by Agent and check;
4. missing intervals beyond two expected samples;
5. active alerts/incidents, pending approvals, and failed notification deliveries;
6. latest uploaded and verified recovery points;
7. Controller, Agent, Web, and Database CPU/RSS;
8. API latency sample and dashboard error rate;
9. NTP synchronization;
10. Guardian/Komari status disagreement without modifying either system.

An unexplained data gap, clock jump, identity duplication, notification loss, or non-Guardian
service drift fails the checkpoint and opens an incident.

## Reports

- 24-hour report: continuity, gaps, false positives/negatives, resource percentiles, notification
  delivery, repair/approval activity, backup state, and decision.
- Daily report: same fields plus version drift and cumulative incident review.
- Seven-day report: daily summaries, sustained resource cost, MTTR, alert churn, data completeness,
  fleet distribution, and a final observation gate.

The report generator must use `null`/`Pending` for missing measurements. It must not substitute zero.

## Current gate

| Gate | Status | Reason |
| --- | --- | --- |
| Existing 24h data range | Present | Row timestamps span more than 24h |
| Verified 24h continuity | Pending | Formal gap and clock analysis not yet completed |
| Verified 7d continuity | Pending | Available Guardian range is shorter than seven days |
| Large-fleet observation | Pending | Two active Guardian Agents |
| Guardian/Komari parallel observation | Pending | No full comparable window yet |

No deployment or report may label the seven-day gate passed until real time and evidence satisfy
this document.
