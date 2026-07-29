# Port traffic design comparison

## Sources reviewed

- `duya07/port-traffic-dog` at
  `c8c91c527fc4beb11e48e9c6fde4627f75fc2dd2`.
- its documented upstream `zywe03/realm-xwPF` at
  `e5dc720fb64b41bfd449cc84fc0c17d7b09b910d`, which includes an MIT License
  (Copyright 2025 zywe).

The customized repository did not include a LICENSE file. Guardian therefore treated
it as a design reference only and traced licensing to the stated upstream. No large
function, script body, notification implementation, installer, or configuration export
was copied. Guardian code in this change is an independent Apache-2.0 implementation.

## Honest comparison

`port-traffic-dog` is strong for one-machine operation: its shell workflow exposes
nftables counters, quotas, resets, snapshots, cron locking, TC controls, migration,
rollback, uninstall, and direct Telegram/WeCom notification choices in one place.
For an operator who accepts root scripts and local configuration, that can be simpler.

Guardian is designed for a managed fleet: non-root Agent, mTLS, signed expiring tasks,
RBAC, independent approval, append-only audit/reset events, PostgreSQL history,
bounded rollups, Web workflows, centralized alert state, and backup/restore controls.
It deliberately does not embed notification secrets in the network helper or use cron
as the source of truth.

The following are measured locally: unit-test correctness and test runtimes. Real
nftables/TC throughput, resource use at 0/1/10/64 policies, restart recovery, and
two-VPS behavior remain unmeasured until isolated Linux Staging. There is no claim of
overall superiority.
