from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated

import pyotp
import typer
from sqlalchemy import select

from guardian.agent_crl import generate_agent_crl, read_serial_file
from guardian.agent_pki import AgentCertificateError
from guardian.audit import write_audit
from guardian.config import get_settings
from guardian.database import SessionLocal
from guardian.models import Host, Role, User
from guardian.security import encrypt_sensitive, hash_password

app = typer.Typer(no_args_is_help=True, help="Bootstrap and maintain controller identities.")


@app.callback()
def main() -> None:
    """Select an identity-maintenance command."""


def _password_from_file(path: Path) -> str:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise typer.BadParameter("password file must be an absolute regular file")
    if path.stat().st_size > 4096:
        raise typer.BadParameter("password file is unexpectedly large")
    password = path.read_text(encoding="utf-8").strip()
    if len(password) < 14:
        raise typer.BadParameter("password must contain at least 14 characters")
    return password


@app.command("create-user")
def create_user(
    email: Annotated[str, typer.Option(prompt=True)],
    password: Annotated[
        str,
        typer.Option(prompt=True, hide_input=True, confirmation_prompt=True),
    ],
    role: Annotated[Role, typer.Option()] = Role.owner,
    enable_totp: Annotated[bool, typer.Option()] = True,
) -> None:
    if len(password) < 14:
        raise typer.BadParameter("password must contain at least 14 characters")
    settings = get_settings()
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.email == email.lower())):
            raise typer.BadParameter("user already exists")
        secret = pyotp.random_base32() if enable_totp else None
        user = User(
            email=email.lower(),
            password_hash=hash_password(password),
            role=role.value,
            totp_enabled=enable_totp,
            totp_secret_encrypted=encrypt_sensitive(secret, settings) if secret else None,
        )
        db.add(user)
        db.commit()
        typer.echo(f"created user {user.email} with role {user.role}")
        if secret:
            typer.echo("TOTP setup URI (displayed once):")
            typer.echo(
                pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="VPS Guardian")
            )


@app.command("ensure-user")
def ensure_user(
    email: Annotated[str, typer.Option()],
    password_file: Annotated[Path, typer.Option("--password-file")],
    role: Annotated[Role, typer.Option()] = Role.owner,
) -> None:
    """Create a non-TOTP bootstrap user idempotently with a password read from a file."""
    password = _password_from_file(password_file)
    get_settings()
    normalized_email = email.lower()
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == normalized_email))
        if existing:
            typer.echo(f"user {normalized_email} already exists; password was not changed")
            return
        user = User(
            email=normalized_email,
            password_hash=hash_password(password),
            role=role.value,
            totp_enabled=False,
            totp_secret_encrypted=None,
        )
        db.add(user)
        db.commit()
        typer.echo(f"created bootstrap user {user.email} with role {user.role}")


@app.command("configure-staging-host")
def configure_staging_host(
    host_name: Annotated[str, typer.Option("--host")],
    stage_id: Annotated[str, typer.Option("--stage-id")],
    level2_enabled: Annotated[bool, typer.Option("--level2-enabled")] = False,
    execute: Annotated[bool, typer.Option("--execute")] = False,
    confirmation: Annotated[str, typer.Option("--confirm")] = "",
) -> None:
    """Enable the isolated acceptance reconciler for one enrolled staging host."""
    if not execute or confirmation != "CONFIGURE VPS GUARDIAN STAGING HOST":
        raise typer.BadParameter("exact staging confirmation and --execute are required")
    if not re.fullmatch(r"[a-f0-9]{32}", stage_id):
        raise typer.BadParameter("stage ID must contain 32 lowercase hexadecimal characters")
    with SessionLocal() as db:
        host = db.scalar(select(Host).where(Host.name == host_name))
        if not host:
            raise typer.BadParameter("enrolled host was not found")
        existing_stage = host.labels.get("guardian_stage_id")
        if existing_stage and existing_stage != stage_id:
            raise typer.BadParameter("host is already bound to another staging identity")
        host.labels = {
            **host.labels,
            "guardian_profile": "staging_acceptance",
            "guardian_stage_id": stage_id,
            "guardian_level2_caddy": "true" if level2_enabled else "false",
        }
        write_audit(
            db,
            actor=None,
            action="host.staging_profile",
            resource_type="host",
            resource_id=host.id,
            outcome="success",
            details={"level2_caddy": level2_enabled, "stage_id_suffix": stage_id[-8:]},
        )
        db.commit()
        typer.echo(
            f"configured staging profile for {host.name}; "
            f"Level 2 Caddy={'enabled' if level2_enabled else 'disabled'}"
        )


@app.command("record-crl-publication")
def record_crl_publication(
    crl_number: Annotated[str, typer.Option("--crl-number")],
    checksum_sha256: Annotated[str, typer.Option("--sha256")],
    certificate_serial: Annotated[str, typer.Option("--certificate-serial")],
    outcome: Annotated[str, typer.Option()],
    reason_code: Annotated[str, typer.Option("--reason-code")],
    execute: Annotated[bool, typer.Option("--execute")] = False,
    confirmation: Annotated[str, typer.Option("--confirm")] = "",
) -> None:
    """Append a bounded, non-secret Agent CRL publication audit event."""
    if not execute or confirmation != "RECORD VPS GUARDIAN CRL PUBLICATION":
        raise typer.BadParameter("exact CRL audit confirmation and --execute are required")
    if crl_number != "unknown" and not re.fullmatch(r"[0-9]{1,40}", crl_number):
        raise typer.BadParameter("CRL number must be decimal or unknown")
    if not re.fullmatch(r"[a-f0-9]{64}", checksum_sha256):
        raise typer.BadParameter("CRL SHA-256 is invalid")
    if not re.fullmatch(r"[A-Fa-f0-9]{1,128}", certificate_serial):
        raise typer.BadParameter("certificate serial is invalid")
    normalized_serial = certificate_serial.upper().lstrip("0") or "0"
    if outcome not in {"attempt", "success", "failure", "rollback"}:
        raise typer.BadParameter("CRL audit outcome is invalid")
    if not re.fullmatch(r"[a-z0-9_.-]{1,64}", reason_code):
        raise typer.BadParameter("CRL reason code is invalid")
    with SessionLocal() as db:
        entry = write_audit(
            db,
            actor=None,
            action="gateway.crl_publication",
            resource_type="agent_ca_crl",
            resource_id=crl_number,
            outcome=outcome,
            details={
                "crl_number": crl_number,
                "sha256": checksum_sha256,
                "certificate_serial": normalized_serial,
                "reason_code": reason_code,
            },
        )
        db.commit()
        typer.echo(f"recorded CRL publication audit id={entry.id} outcome={outcome}")


@app.command("build-agent-crl")
def build_agent_crl(
    current_crl: Annotated[Path, typer.Option("--current-crl")],
    serial_file: Annotated[Path, typer.Option("--serial-file")],
    output: Annotated[Path, typer.Option("--output")],
    execute: Annotated[bool, typer.Option("--execute")] = False,
    confirmation: Annotated[str, typer.Option("--confirm")] = "",
) -> None:
    """Build a signed, monotonic Agent CRL candidate without publishing it."""
    if not execute or confirmation != "BUILD VPS GUARDIAN AGENT CRL":
        raise typer.BadParameter("exact Agent CRL confirmation and --execute are required")
    for path, label in ((current_crl, "current CRL"), (output, "output")):
        if not path.is_absolute():
            raise typer.BadParameter(f"{label} path must be absolute")
    if current_crl.is_symlink() or not current_crl.is_file():
        raise typer.BadParameter("current CRL must be a regular file")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise typer.BadParameter("output must be a new file in an existing directory")
    try:
        generated = generate_agent_crl(
            current_crl_pem=current_crl.read_bytes(),
            revoked_serial=read_serial_file(serial_file),
            settings=get_settings(),
        )
        descriptor = os.open(
            output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(generated.pem)
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, AgentCertificateError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(
        f"built Agent CRL candidate number={generated.number} sha256={generated.sha256}"
    )


if __name__ == "__main__":
    app()
