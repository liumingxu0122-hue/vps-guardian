# Port traffic operations

## Install or upgrade

Build `./agent/nethelper` for the target architecture and obtain its SHA-256 from the
trusted release manifest. On an isolated Linux node run:

```sh
sudo scripts/install-port-traffic-helper.sh \
  --binary /verified/path/vps-guardian-net-helper \
  --sha256 <64-lowercase-hex>
```

The installer verifies the artifact and systemd units, writes a root-only hashed
rollback backup, installs the socket-activated helper, and fails closed. Then set:

```json
{"port_traffic_enabled":true,"net_helper_socket":"/run/vps-guardian-net-helper/helper.sock"}
```

in the existing Agent configuration and restart only the Agent. Do not enable this
feature automatically during a generic Agent upgrade. The same root-owned
configuration must contain the Controller-issued `host_id`; the helper compares it
with every signed task target and refuses a mismatch.

The first release supports systemd socket activation only. The repository has no
existing OpenRC Agent lifecycle, so an OpenRC privileged-helper service is not claimed
or generated; it remains a separately gated portability task.

## Policy workflow

1. Create a monitor-only policy in Web and verify exact RX/TX samples.
2. Observe at least one full expected reset boundary or perform an approved reset.
3. Create a high-risk request for enforcement or egress shaping.
4. A different Admin/Owner verifies rollback and approves with step-up.
5. Verify task result, owned rules, counter continuity, alerts, and audit.

Manual reset requires `RESET <policy UUID>` when requesting and again at approval.
A scheduled reset cannot be selected during policy creation or edited directly. Its
schedule is a dedicated high-risk change: one Admin/Owner requests it and a different
Admin/Owner approves it with `SCHEDULE <policy UUID>`. The Controller persists that
approval provenance and queues due resets only while it remains complete. Schedules
are evaluated in the configured timezone; event and storage timestamps remain UTC.

## Rollback and uninstall

Disable enforcement first through an approved change. Restore the installer backup if
an upgrade fails. To uninstall:

```sh
sudo scripts/uninstall-port-traffic-helper.sh
```

The script backs up and hashes local state, asks the helper to remove Guardian-owned
nftables/TC objects, removes socket units and the binary, and preserves local state.
`--purge-local-state` is explicit and does not delete Controller history or audit.

## Retention

Run `prune_port_traffic` from the Controller maintenance path: raw 7 days, hourly 90
days, daily 400 days. Never delete reset/audit events through retention.
