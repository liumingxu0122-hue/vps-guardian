# Port traffic security model

## Trust boundary

The Agent remains non-root with `NoNewPrivileges=yes` and no capabilities. It sends
one bounded JSON request to `/run/vps-guardian-net-helper/helper.sock`. The socket is
owned by root, group-readable/writable only by `vps-guardian-agent`, and starts a fresh
root oneshot service for each connection.

The helper:

- accepts only `snapshot`, `apply`, `remove`, `reset`, and root-local `purge`;
- validates every field, UUID, protocol, direction, port range, interface, quota, rate,
  generation, and maximum policy count;
- never accepts a command, executable path, URL, token, Cookie, key, or shell string;
- executes `nft` and `tc` with argument arrays and sends nftables rules over stdin;
- owns only table `inet vps_guardian_port_traffic` and TC handle `7a11:`;
- rejects shaping when an existing root qdisc is not Guardian-owned;
- has no Internet address family and receives only `CAP_NET_ADMIN`;
- writes only `/var/lib/vps-guardian-net-helper` and `/run/lock`.

The unit also uses strict filesystem, home, temporary-directory, kernel, control-group,
SUID/SGID, personality, realtime, and executable-memory restrictions. A static
`SystemCallFilter` was evaluated but is not enabled in the first release because the
syscall surface of distro `nft`/`tc` versions varies; the fixed executable/argument
model, address-family restriction, capability bound, and isolated Linux gate remain
mandatory until a portable allowlist is validated.

## Authorization

Viewer can read summaries and bounded history. Admin/Owner can create or update
monitor-only policies after step-up. Quota enforcement, manual reset, scheduled-reset
configuration, and TC shaping require a high-risk approval whose requester and
approver differ. Scheduled execution also fails closed unless its stored request and
approval provenance is complete. The signed task binds action, parameters, approval,
actors, target host, nonce, and a 30–900 second expiry. The helper also compares the
signed target host with the root-owned local Agent configuration. Invalid, expired,
replayed, self-approved, mismatched-target, or host-unbound tasks fail closed.

## Atomicity and rollback

Before rebuilding Guardian-owned rules, the helper absorbs current kernel counters
into durable cumulative offsets. nftables receives one transaction. TC is applied
after nftables; any TC or state-commit failure restores the prior owned nftables/TC
state with absorbed counters. Unrelated firewall tables and qdiscs are never flushed.

The helper is not a general firewall manager. Controller history, reset events, and
audit records are append-only or retained independently from kernel objects.

## Residual risks

Kernel/tool-version compatibility and hostile local root are outside this boundary.
TC cannot be fully atomic with nftables, so rollback is compensating rather than a
single kernel transaction. These risks require isolated Linux Staging before merge.
