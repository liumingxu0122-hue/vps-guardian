from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from guardian.trust_material import (
    TrustMaterialError,
    TrustMaterialPaths,
    export_controller_public_key,
    verify_trust_material_manifest,
    write_trust_material_manifest,
)


def _add_material_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-ca", required=True, type=Path)
    parser.add_argument("--agent-crl", required=True, type=Path)
    parser.add_argument("--controller-signing-key", required=True, type=Path)
    parser.add_argument("--controller-public-key", required=True, type=Path)
    parser.add_argument("--gateway-certificate", required=True, type=Path)
    parser.add_argument("--gateway-issuer-ca", required=True, type=Path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardian-trust-material")
    commands = parser.add_subparsers(dest="command", required=True)

    export = commands.add_parser("export-controller-public-key")
    export.add_argument("--controller-signing-key", required=True, type=Path)
    export.add_argument("--controller-public-key", required=True, type=Path)
    export.add_argument("--replace", action="store_true")

    write = commands.add_parser("write")
    _add_material_paths(write)
    write.add_argument("--manifest", required=True, type=Path)
    write.add_argument("--previous-crl", type=Path)
    write.add_argument("--replace", action="store_true")

    verify = commands.add_parser("verify")
    _add_material_paths(verify)
    verify.add_argument("--manifest", required=True, type=Path)
    return parser


def _paths(arguments: argparse.Namespace) -> TrustMaterialPaths:
    return TrustMaterialPaths(
        agent_ca=arguments.agent_ca,
        agent_crl=arguments.agent_crl,
        controller_signing_key=arguments.controller_signing_key,
        controller_public_key=arguments.controller_public_key,
        gateway_certificate=arguments.gateway_certificate,
        gateway_issuer_ca=arguments.gateway_issuer_ca,
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "export-controller-public-key":
            export_controller_public_key(
                arguments.controller_signing_key,
                arguments.controller_public_key,
                replace=arguments.replace,
            )
        elif arguments.command == "write":
            write_trust_material_manifest(
                _paths(arguments),
                arguments.manifest,
                previous_crl=arguments.previous_crl,
                replace=arguments.replace,
            )
        else:
            verify_trust_material_manifest(_paths(arguments), arguments.manifest)
    except TrustMaterialError as exc:
        print(f"trust material validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
