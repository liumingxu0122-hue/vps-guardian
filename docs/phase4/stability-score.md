# Stability score

The stability score is a diagnostic summary. It never replaces the current host state, an active
alert, or an incident decision.

## Windows and eligibility

The API accepts `1h`, `24h`, `7d`, and `30d`. Disabled hosts are excluded from fleet aggregates.
Hosts with no observations in a window return `null` for scores rather than an invented zero or
perfect score.

Each eligible host exposes:

- uptime score: share of recent heartbeats that are not stale;
- heartbeat score: observed heartbeat coverage relative to the configured interval;
- check-success score: successful service checks divided by completed checks;
- failure rate: failed checks divided by completed checks;
- mean recovery time: mean duration between a firing alert and its recovery;
- stale ratio: stale heartbeat observations divided by expected observations;
- alert frequency: alerts opened per observed hour;
- confidence: bounded evidence coverage for the selected window;
- stability score: a confidence-smoothed weighted summary.

## Formula

Available component scores are normalized to 0–100:

```text
raw =
  0.35 × uptime_score
  + 0.25 × heartbeat_score
  + 0.25 × check_success_score
  + 0.15 × alert_component

alert_component = max(0, 100 - min(100, alert_frequency × 20))

stability_score =
  confidence × raw
  + (1 - confidence) × 75
```

Missing components are removed and the remaining weights are normalized. The prior of 75 prevents
a new host with a few successful samples from immediately appearing perfect, and also prevents one
short interruption from producing an extreme long-term score. The API still returns the individual
components and confidence so operators can see why the summary moved.

## Aggregation

Fleet, group, and location aggregates use only enabled hosts with usable evidence. An empty
aggregate is `null`, not zero. A low-confidence aggregate must be shown as low confidence. Ranking
must display confidence and the active operational state beside the score.

## Interpretation

- Current state answers “what is happening now?”
- Stability score answers “how consistently has this object behaved in this window?”
- Confidence answers “how much evidence supports that summary?”

An online host may have a poor historical score. An offline host may still have a strong 30-day
score. The UI must not collapse those statements into one color or one label.
