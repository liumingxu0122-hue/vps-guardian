# Agent installation

[English](AGENT_INSTALLATION.md) | [简体中文](../zh-CN/AGENT_INSTALLATION.md)

Create the host inventory entry in the Dashboard, then generate a short-lived enrollment bundle through the Controller's authorized workflow. Transfer it over a protected channel and verify its checksum before use.

Install the versioned `guardian-agent` binary for `linux-amd64` or `linux-arm64`, a root-owned configuration file, CA trust material, and the systemd unit. Private keys must be mode `0600`; configuration and public trust material should be root-owned and not writable by other users.

Start the service and verify that the Dashboard reports a fresh heartbeat, the expected certificate serial, metrics, and an empty offline queue. Revoke enrollment material after use. Never reuse one Agent identity across hosts, disable certificate verification, or copy keys into Git, shell history, logs, or support bundles.

Certificate rotation and revocation are Controller-governed operations. Preserve the previous trust set until the replacement identity has completed a verified heartbeat.
