# Quick start

[English](QUICKSTART.md) | [简体中文](../zh-CN/QUICKSTART.md)

This guide creates a single-node Developer Preview deployment. It is not a production hardening guide.

## Install

Install Docker Engine 27+, Docker Compose v2, Git, OpenSSL, Python 3, and `flock`. Prepare separate DNS names for the dashboard and Agent ingress.

```sh
git clone https://github.com/liumingxu0122-hue/vps-guardian.git
cd vps-guardian
cp .env.example .env
chmod 0600 .env
# Replace every example value in .env; do not place secrets there.
sudo sh scripts/generate-controller-secrets.sh ./secrets agents.guardian.example.com
sudo sh scripts/prepare-compose-secrets.sh --secrets-dir "$(pwd)/secrets"
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
docker compose exec -it controller guardian-admin create-user
```

The administrator command prompts for email, role, TOTP choice, and a hidden password. Never put passwords in argv, `.env`, Git, shell history, or logs. Wait until `database`, `controller`, `agent-gateway`, and `web` are healthy, then open `https://<GUARDIAN_DOMAIN>/overview`.

For upgrades, verify a backup and restore first, inspect `CHANGELOG.md`, check out an explicit version, rebuild, and recreate only Guardian services. To uninstall while retaining data, run `docker compose down`; volume deletion is intentionally excluded.

The Windows SSH dashboard launcher is Experimental and requires explicit SSH target, identity path, dashboard domain, and remote port.
