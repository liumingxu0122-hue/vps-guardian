# Public read-only staging panel

The public panel is an optional, deliberately limited view for a non-production staging
deployment. It is not a production feature and does not change the production **NO-GO**
decision.

## Deployment separation

- A protected panel, including `panel.liuwave.com`, keeps
  `GUARDIAN_ANONYMOUS_READ_ONLY=false`. Its existing login, session, CSRF, and RBAC behavior
  remains unchanged.
- A separate public staging deployment must explicitly set:

  ```dotenv
  GUARDIAN_DEPLOYMENT_STAGE=staging
  GUARDIAN_PRODUCTION_DEPLOYED=false
  GUARDIAN_ANONYMOUS_READ_ONLY=true
  ```

`GUARDIAN_ENVIRONMENT=production` selects the hardened runtime rules used by Compose. It does
not mean the staging deployment is production. `GUARDIAN_DEPLOYMENT_STAGE` identifies the
deployment tier. The Controller refuses to start when anonymous mode is enabled for any tier
other than staging or when production is marked deployed.

## Public boundary

Anonymous access is implemented by dedicated public endpoints, not by granting the existing
viewer role:

- `GET`, `HEAD`, and preflight `OPTIONS` for `/api/v1/public/session`
- `GET`, `HEAD`, and preflight `OPTIONS` for `/api/v1/public/overview`
- `GET`, `HEAD`, and preflight `OPTIONS` for `/api/v1/public/hosts`

All other API routes keep their existing authentication and RBAC requirements. The public Web
navigation contains only Overview and Hosts. Host detail snapshots, services, alerts,
incidents, repairs, approvals, recovery, audit, settings, Agent identity, enrollment, and
notification pages are not public.

Public response models declare allowed fields directly. They contain display name, optional
location, health state, last-seen time, and bounded CPU, memory, and disk percentages. They do
not contain addresses, operating-system inventory, groups, tags, labels, raw Agent payloads,
service configuration, incident evidence, certificate data, queues, internal topology,
recovery metadata, security findings, audit records, secrets, tokens, or repair data.

## Credential behavior

Only a Bearer token or the `guardian_session` authentication cookie is an explicit credential.
If either is present, it must validate successfully; invalid and expired credentials return
`401` and never fall back to anonymous access. Other cookies, including language and theme
preferences, do not participate in authentication.

Public responses use `Cache-Control: no-store`. Operators should retain the existing trusted
host and allowed-origin restrictions and must not enable this mode on a production or protected
panel.

## Validation status

Automated tests use only local test applications and synthetic data. The real protected panel
test is opt-in and skipped by default. Enabling this feature does not authorize a deployment,
DNS change, panel switch, or production rollout.
