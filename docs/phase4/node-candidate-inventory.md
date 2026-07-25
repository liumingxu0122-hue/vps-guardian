# Phase 4 sanitized node candidate inventory

This is a read-only union of the Guardian and Komari inventories captured on
2026-07-25. It excludes addresses, UUIDs, tokens, Agent identities, remarks, and
credentials. `Unknown` means the field was not proven and must not be inferred.
No node in this document is approved for installation or certificate mutation.

Komari `recent` means the inventory row updated during the audit window. `Stale`
is not treated as an outage diagnosis, but stale/current-fault candidates are
excluded from rollout.

| Host | Region | OS | Init | Docker | Guardian | Komari | Proxy business | Risk | Certificate test | Batch 1 | Batch 2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CH-broadcast-01` | CH | Alpine 3.21 | Unknown | Unknown | Imported; pending enrollment | Recent | Likely by name; unverified | High | No | No | No |
| `HK-native-01` | HK | Ubuntu 22.04.5 | Unknown | Unknown | Not imported | Recent | Unknown | Medium | No | No | **Provisional** |
| `JP-broadcast-01` | JP | Debian 13 | Unknown | Unknown | Imported; pending enrollment | Recent | Likely by name; unverified | High | No | No | No |
| `SG-broadcast-01` | SG | Debian 12 | Unknown | Unknown | Imported; pending enrollment | Recent | Likely by name; unverified | High | No | No | No |
| `TW-broadcast-02` | TW | Alpine 3.21 | Unknown | Unknown | Imported; pending enrollment | Recent | Likely by name; unverified | High | No | No | No |
| `TW-broadcast-03` | TW | Alpine 3.21 | Unknown | Unknown | Disabled; `do_not_enroll` | Recent | Likely by name; unverified | High | No | No | No |
| `TW-home-01` | TW | Debian 11 | Unknown | Unknown | Imported; pending enrollment | Stale | Unknown | High | No | No | No |
| `US-broadcast-05` | US | Ubuntu 22.04.5 | Unknown | Unknown | Imported; pending enrollment | Stale | Likely by name; unverified | High | No | No | No |
| `US-native-01` | US | Ubuntu 22.04.5 | Unknown | Unknown | Not imported | Recent | Unknown | Medium | No | No | **Provisional** |
| `US-native-02` | US | Ubuntu 22.04.1 | Unknown | Unknown | Imported; pending enrollment | Recent | Unknown | Medium | No | **Provisional** | No |
| `US-native-03` | US | Debian 12 | Unknown | Unknown | Imported; pending enrollment | Stale | Unknown | High | No | No | No |
| `US-native-04` | US | Debian 12 | Unknown | Unknown | Imported; pending enrollment | Stale | Unknown | High | No | No | No |
| `US-native-05` | US | Alpine 3.21 | Unknown | Unknown | Imported; pending enrollment | Recent | Unknown | Medium | No | **Provisional** | No |
| `staging-agent` | Controller-local fixture | Linux, exact release unknown | systemd host | Present on host | Enrolled; healthy; Staging acceptance profile | Not listed | No evidence of proxy role | Medium | **Provisional** | No | No |
| `vg-stg-controller` | Staging Controller | Linux | systemd | Present | Enrolled; heartbeat stale | Local Komari Agent active | Unique management node | Critical | No | No | No |

## Selection rationale

### Dedicated certificate-test Agent

`staging-agent` is the only record explicitly labeled for Staging acceptance and
is managed by a dedicated fixture service. It is a candidate only if the operator
confirms that:

- certificate changes are limited to the fixture identity;
- the Controller host's management Agent is not selected;
- fixture service rollback and the previous identity are available;
- no proxy or unrelated workload shares the test identity.

If any condition is false, provision a new dedicated disposable Agent instead.

### Batch 1

`US-native-02` and `US-native-05` are recent in Komari and already present as
pending Guardian inventory records. Before approval, the user must confirm:

- neither carries critical proxy traffic;
- direct SSH/console rollback exists;
- init and package architecture are supported;
- disk and service health are normal;
- one node is completed and observed before touching the second.

### Batch 2

`HK-native-01` and `US-native-01` are recent in Komari but are not yet imported
into Guardian. They remain later-batch candidates because inventory import,
rollback access, and business role need confirmation.

## Explicit exclusions

- all `broadcast` nodes until the user proves they are non-critical and approves
  them;
- `TW-broadcast-03`, because it is explicitly paused and `do_not_enroll`;
- stale Komari nodes;
- `vg-stg-controller`, because it is the unique management node;
- every unapproved node, regardless of apparent health.

No batch may begin from this document alone.
