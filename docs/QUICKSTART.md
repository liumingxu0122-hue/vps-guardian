# Quick start

This guide creates a single-node Developer Preview deployment. It is not a production hardening guide.

## 1. Prepare DNS and the host

Point one DNS name at the host for the dashboard and another for Agent ingress. Install Docker Engine, Docker Compose v2, Git, OpenSSL, Python 3, and `flock`. Allow dashboard ports 80/443 and the selected Agent gateway port only from intended networks.

## 2. Configure public values

```sh
git clone https://github.com/<your-account>/vps-guardian.git
cd vps-guardian
cp .env.example .env
chmod 0600 .env
```

Edit `.env`. Replace all `example.com` values. Do not add secrets. Set `VPS_GUARDIAN_SOURCE_COMMIT` to `git rev-parse HEAD` before building release images.

## 3. Generate file-based secrets and PKI

```sh
sudo sh scripts/generate-controller-secrets.sh ./secrets agents.guardian.example.com
sudo sh scripts/prepare-compose-secrets.sh --secrets-dir "$(pwd)/secrets"
```

The second argument must exactly match `GUARDIAN_AGENT_DOMAIN`. The scripts refuse to overwrite a non-empty secret directory. Store an encrypted off-host copy of the CA, field encryption key, signing key, and Restic password.

## 4. Build and start

```sh
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
```

Wait until `database`, `controller`, `agent-gateway`, and `web` are healthy.

## 5. Create the first administrator

Interactive mode is preferred:

```sh
docker compose exec -it controller guardian-admin create-user
```

The command prompts for email, role, TOTP choice, and a hidden password with confirmation. For unattended bootstrap, create a root-only temporary password file and mount or copy it into the Controller through a controlled local process, then run:

```sh
guardian-admin ensure-user --email admin@example.com --password-file /absolute/root-only/file
```

Never place a password in argv, `.env`, Compose YAML, Git, shell history, or logs. Delete the temporary password file after success. The command does not replace an existing user's password.

## 6. Sign in and enroll Agents

Open `https://<GUARDIAN_DOMAIN>/overview`, sign in, and complete TOTP setup when enabled. Continue with [Agent installation](AGENT_INSTALLATION.md).

## Upgrade

Back up and verify restore first. Fetch the desired version, inspect `CHANGELOG.md`, set explicit versioned image names, rebuild, run migrations through the existing Controller entrypoint, and recreate VPS Guardian services. Do not use a floating `latest` tag.

## Uninstall

```sh
docker compose down
```

This preserves named volumes. Removing volumes permanently destroys data and is intentionally omitted from the quick path.

## Experimental Windows SSH launcher

`scripts/windows/Open-VpsGuardianDashboard.ps1` creates a temporary SSH tunnel and isolated Edge profile without changing the hosts file. It is Experimental and must be validated in your environment. Pass the SSH target, identity path, dashboard domain, and remote HTTPS port explicitly.
