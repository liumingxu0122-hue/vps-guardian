# Port traffic accounting

## Scope

VPS Guardian records exact kernel byte counters for explicit TCP/UDP ports or bounded
port ranges. RX and TX are stored separately; the combined value is `RX + TX` with no
weighting. The first release supports monitoring, optional quota enforcement, and
optional egress-only TC shaping. Ingress shaping and IFB are future work.

Every policy starts as `monitor_only`. A policy selects one host, protocol, direction,
ports, optional interface, optional byte quota, reset schedule, and optional egress
rate. Overlapping active protocol/port scopes are rejected and each host is limited to
64 policies.

## Data model and retention

PostgreSQL migration `0013_port_traffic` adds policy, raw sample, hourly rollup, daily
rollup, reset event, and runtime-state tables. Raw data is retained for 7 days, hourly
rollups for 90 days, and daily rollups for 400 days. History requests are bounded to
400 days and 10,000 points.

Counters are cumulative in the helper. Controller deltas are accepted only when the
generation is unchanged and both counters are monotonic. A generation change, counter
decrease, missing rule, or missed heartbeat is an explicit discontinuity. The initial
sample is a baseline and is omitted from interval history; it is never reported as
zero traffic.

Each batched policy observation includes exact RX, TX, and combined lifetime/current
period totals, quota value/percentage/state, reset policy and boundaries, generation,
runtime/shaping state, reliable egress rate, collection time, and any discontinuity.
The Controller recomputes accounting and quota decisions from the primitive counters;
it does not trust Agent-derived totals for billing or enforcement decisions.

All timestamps are stored in UTC. Reset schedules include an IANA timezone and clamp
invalid month-end days. The Web UI renders the user's local timezone, including DST,
while hourly and daily storage buckets remain UTC. A non-manual schedule becomes
active only through an independently approved schedule-change request; direct create
or update attempts fail closed.

## Alerts

Quota rules use the existing persisted alert state machine at 70%, 85%, 95%, and
100%. Recovery uses a 2 percentage-point hysteresis and the existing notification
deduplication/recovery path. Missing rules and sample gaps remain visible as runtime
degradation; they are not synthesized into usage.

## Status

Unit-tested Controller, Agent, helper, and Web behavior is implemented. Real kernel
nftables/TC behavior, resource budgets at 0/1/10/64 policies, and two-VPS Staging
acceptance remain gates. Production is **NO-GO**.
