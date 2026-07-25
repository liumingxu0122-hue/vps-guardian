# Phase 4 production gate

Production is **NO-GO** by default. Code completion, a pull request, or a successful Staging build
does not change this decision.

Current evidence:

- [pre-deployment Staging drift](staging-drift-before.md);
- [Phase 4 Staging acceptance report](staging-acceptance-report.md).

| Gate | Evidence required | Current status |
| --- | --- | --- |
| Phase 3 security | live CRL handshake rejection, fail-closed reload, rotation | NO-GO |
| Phase 3 disaster recovery | current off-site backup and isolated restore | NO-GO |
| Current RPO/RTO | measured current exercise, not historical values | NO-GO |
| UI V2 and core pages | automated, accessibility, and visual evidence | GO in code and disposable environment; real Staging pending |
| Stability model | formula, API, tests, UI components | Code complete |
| Alert/incident workflow | durable transitions, assignment, audit | Code complete |
| Restricted repair/approval | allowlisted actions and staged verification | Existing preview; Staging revalidation pending |
| Agent lifecycle | CSR, renewal, revocation, update/rollback | Two-Agent historical evidence only |
| Multi-user/RBAC | role ceiling, scopes, reauth, session revocation | Disposable Owner/Viewer tests passed; real Staging pending |
| External notifications | two real channels through event/retry/recovery/dead-letter | NO-GO |
| Multi-VPS Staging | phased fleet across platforms without Komari removal | NO-GO |
| 24-hour observation | continuous valid data and report | Pending |
| Seven-day observation | continuous valid data and report | Pending |
| Nezha 2.3.0 comparison | official-source study plus isolated runtime measurements | Study complete; benchmark pending |
| Cross-cloud restore | recovery in a different failure domain | NO-GO |
| Staging rollback | measured database/application rollback exercise | NO-GO |
| Security scans | Critical 0; remediated/accepted High; Gitleaks; SBOM | GO on PR checks |
| Documentation/runbooks | reviewed bilingual operations set | Complete in branch; review pending |
| Human authorization | signed production authorization table | Not granted |

The fixed candidate commit `108d7880e9f5f1b5455245be927ea7fb02d8346f`
was built as `0.4.0-phase4-rc1`. Empty-database and restored-real-data-copy
migration cycles, disposable login/RBAC/API tests, and all 16 SPA deep links
passed. The existing authenticated Staging deployment was deliberately left
unchanged because it has only one active Owner, no TOTP-enabled recovery Owner,
no secure replacement-password delivery path, and no off-site Restic backend.
The validated same-host snapshot and restore do not satisfy the cross-cloud
recovery gate.

The historical Phase 3E `RPO ≈ 16s` and `RTO ≈ 50s` are accepted historical snapshots only.

## Required authorization table

Before setting `operations_gate_decision=approved_for_production`, record:

- reviewed immutable commit and images;
- security reviewer and decision time;
- disaster-recovery reviewer and decision time;
- operations reviewer and decision time;
- observation report identifiers;
- rollback owner and exact rollback release;
- credential rotation confirmation;
- explicit production approver.

No field may be auto-filled from CI. Approval is an external human decision.

## Current roll-up

- Phase 3 Security: **NO-GO**
- Phase 3 DR: **NO-GO**
- Phase 4 Code: **GO**
- Phase 4 Feature: **NO-GO** until real notifications, fleet, and recovery gates
- Phase 4 UI: **GO** for code and disposable-environment evidence; real-browser
  Staging acceptance pending
- Phase 4 Staging: **NO-GO**
- Phase 4 Observation: **PENDING**
- Production: **NO-GO**
