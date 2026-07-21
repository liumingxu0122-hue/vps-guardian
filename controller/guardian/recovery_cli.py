from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from guardian.backup import BackupError, RecoveryPlanner, ResticAdapter, load_restic_config

app = typer.Typer(
    name="guardian-recovery",
    help="Independent, dry-run-first recovery client for VPS Guardian Restic repositories.",
    no_args_is_help=True,
)

RepositoryOption = Annotated[
    str | None,
    typer.Option("--repository", help="Local absolute path or TLS-protected s3: repository."),
]
PasswordFileOption = Annotated[
    Path | None,
    typer.Option(
        "--password-file",
        help="Protected file containing the Restic repository password.",
    ),
]


def _fail(exc: Exception) -> NoReturn:
    message = str(exc) if isinstance(exc, BackupError) else "recovery operation failed"
    typer.echo(f"recovery error: {message}", err=True)
    raise typer.Exit(code=2)


def _planner(repository: str | None, password_file: Path | None) -> RecoveryPlanner:
    return RecoveryPlanner(
        ResticAdapter(load_restic_config(repository=repository, password_file=password_file))
    )


@app.command("points")
def points(
    repository: RepositoryOption = None,
    password_file: PasswordFileOption = None,
) -> None:
    """List Guardian recovery points without requiring the controller database."""
    try:
        snapshots = _planner(repository, password_file).list_recovery_points()
    except (BackupError, OSError, RuntimeError, ValueError) as exc:
        _fail(exc)
    typer.echo(json.dumps([asdict(item) for item in snapshots], indent=2, ensure_ascii=True))


@app.command("impact")
def impact(
    snapshot_id: Annotated[str, typer.Argument(help="Restic snapshot ID.")],
    repository: RepositoryOption = None,
    password_file: PasswordFileOption = None,
) -> None:
    """Show the files and byte count affected by a restore."""
    try:
        result = _planner(repository, password_file).impact(snapshot_id)
    except (BackupError, OSError, RuntimeError, ValueError) as exc:
        _fail(exc)
    typer.echo(json.dumps(asdict(result), indent=2, ensure_ascii=True))


def _restore(
    *,
    snapshot_id: str,
    target: Path,
    repository: str | None,
    password_file: Path | None,
    execute: bool,
    approval_id: str | None,
    plan_digest: str | None,
    confirmation: str | None,
    scope: str,
) -> None:
    try:
        planner = _planner(repository, password_file)
        plan = planner.plan(snapshot_id, target, scope=scope)
        result = planner.restore(
            snapshot_id,
            target,
            execute=execute,
            approval_id=approval_id,
            plan_digest=plan_digest,
            confirmation=confirmation,
            scope=scope,
        )
    except (BackupError, OSError, RuntimeError, ValueError) as exc:
        _fail(exc)
    mode = "executed" if execute else "dry-run"
    typer.echo(
        json.dumps(
            {
                "status": mode,
                "plan": asdict(plan),
                "output": result.stdout,
            },
            ensure_ascii=True,
        )
    )


@app.command("restore-service")
def restore_service(
    snapshot_id: Annotated[str, typer.Argument(help="Service recovery-point snapshot ID.")],
    target: Annotated[Path, typer.Option("--target", help="New or empty isolation directory.")],
    repository: RepositoryOption = None,
    password_file: PasswordFileOption = None,
    execute: Annotated[
        bool, typer.Option("--execute", help="Perform the isolated restore.")
    ] = False,
    approval_id: Annotated[str | None, typer.Option("--approval-id")] = None,
    plan_digest: Annotated[str | None, typer.Option("--plan-digest")] = None,
    confirmation: Annotated[str | None, typer.Option("--confirm")] = None,
) -> None:
    """Dry-run or restore one service snapshot into an isolation directory."""
    _restore(
        snapshot_id=snapshot_id,
        target=target,
        repository=repository,
        password_file=password_file,
        execute=execute,
        approval_id=approval_id,
        plan_digest=plan_digest,
        confirmation=confirmation,
        scope="service",
    )


@app.command("rebuild-controller")
def rebuild_controller(
    snapshot_id: Annotated[str, typer.Argument(help="Controller recovery-point snapshot ID.")],
    target: Annotated[Path, typer.Option("--target", help="New controller staging directory.")],
    repository: RepositoryOption = None,
    password_file: PasswordFileOption = None,
    execute: Annotated[bool, typer.Option("--execute")] = False,
    approval_id: Annotated[str | None, typer.Option("--approval-id")] = None,
    plan_digest: Annotated[str | None, typer.Option("--plan-digest")] = None,
    confirmation: Annotated[str | None, typer.Option("--confirm")] = None,
) -> None:
    """Restore controller state into a new staging directory; never overwrites a live controller."""
    _restore(
        snapshot_id=snapshot_id,
        target=target,
        repository=repository,
        password_file=password_file,
        execute=execute,
        approval_id=approval_id,
        plan_digest=plan_digest,
        confirmation=confirmation,
        scope="controller",
    )


@app.command("rebuild-host")
def rebuild_host(
    snapshot_id: Annotated[str, typer.Argument(help="Host recovery-manifest snapshot ID.")],
    target: Annotated[Path, typer.Option("--target", help="New host staging directory.")],
    repository: RepositoryOption = None,
    password_file: PasswordFileOption = None,
    execute: Annotated[bool, typer.Option("--execute")] = False,
    approval_id: Annotated[str | None, typer.Option("--approval-id")] = None,
    plan_digest: Annotated[str | None, typer.Option("--plan-digest")] = None,
    confirmation: Annotated[str | None, typer.Option("--confirm")] = None,
) -> None:
    """Restore a host manifest into a new staging directory for a rebuild."""
    _restore(
        snapshot_id=snapshot_id,
        target=target,
        repository=repository,
        password_file=password_file,
        execute=execute,
        approval_id=approval_id,
        plan_digest=plan_digest,
        confirmation=confirmation,
        scope="host",
    )


if __name__ == "__main__":
    app()
