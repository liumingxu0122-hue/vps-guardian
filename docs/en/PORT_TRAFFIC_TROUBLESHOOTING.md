# Port traffic troubleshooting

| Symptom | Read-only checks | Safe response |
|---|---|---|
| No samples | Agent metric `port_traffic_collection_error`, socket status, helper journal | Restore socket/helper; do not enter zero usage |
| Rule `missing` | `nft -j list table inet vps_guardian_port_traffic`, policy/runtime state | Reapply monitor policy; record discontinuity |
| Counter decreases | generation and previous raw sample | Treat as wrap/reset; never subtract into a negative delta |
| Quota alert does not recover | current-period bytes, rule state, 2% hysteresis | Wait for two successful observations below recovery level |
| Shaping rejected | `tc -j qdisc show dev <iface>` | Preserve non-Guardian qdisc; redesign the isolated test |
| Helper request rejected | systemd journal and Agent task result | Correct structured policy; never bypass with shell |
| Upgrade fails | installer backup and SHA256SUMS | Restore binary/units from the exact backup |

Do not fix problems by flushing the host firewall, deleting all qdiscs, recreating Agent
identity, changing DNS/proxies, or reinstalling the node. Capture only redacted
commands and never attach unredacted host exports.

A missing point is unknown, not zero. A reset is a generation boundary, not traffic
loss. A `rule_missing` interval remains visible after restoration.
