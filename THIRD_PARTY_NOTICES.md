# Third-party notices

VPS Guardian source is Apache-2.0 licensed. Dependencies, base images, and tools are separate works and remain governed by their own licenses.

Notable direct dependencies include FastAPI, SQLAlchemy, Alembic, Pydantic, PyJWT, cryptography, psycopg, Vue, Vue Router, Vite, Playwright, Caddy, HAProxy, PostgreSQL, and Restic. Most use MIT, BSD, ISC, or Apache licenses. Psycopg is distributed under LGPL-3.0-only. Cryptography is available under Apache-2.0 OR BSD-3-Clause.

The lockfiles are the authoritative dependency inventory for this release. Review transitive package metadata and container image notices before redistribution.

## Port traffic design study

The port-traffic feature was independently implemented after a design review of
`duya07/port-traffic-dog` commit
`c8c91c527fc4beb11e48e9c6fde4627f75fc2dd2` and its documented upstream
`zywe03/realm-xwPF` commit
`e5dc720fb64b41bfd449cc84fc0c17d7b09b910d`. The customized repository did not
contain a LICENSE; the upstream contains an MIT License (Copyright 2025 zywe).
No substantial script/function, notification code, installer, or configuration export
from either repository is included in VPS Guardian.
