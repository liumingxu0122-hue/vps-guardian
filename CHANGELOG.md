# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and Semantic Versioning prerelease conventions.

## [Unreleased]

### Added

- Added decision-oriented Approval summary/detail DTOs, bounded lifecycle timelines,
  structured impact and execution steps, lazy redacted evidence, and bilingual,
  responsive Approval Center regressions.
- Added the Phase 4 UI V3 product shell, shared design tokens, responsive/focus-trapped
  navigation and detail drawers, lightweight dashboard bootstrap/current-resource
  APIs, URL-persisted operational filters, and audited Service-check batch updates.
- Added a reversible `0011_dashboard_query_indexes` migration, user-isolated
  10-second dashboard cache, ETag/304 handling, `Server-Timing`, production
  sourcemap exclusion, axe/Playwright product regressions, and an internal
  `vps-guardian-product-ui` design-review Skill.
- Added the Phase 4 V2 grouped operations console, Attention queue, topology/security/user/Agent/notification pages, breadcrumbs, command palette, responsive drawer, and light/dark tokens.
- Added explainable deployment health, 1h/24h/7d/30d stability components, confidence, group/location aggregates, and bounded service-check history.
- Added persistent alert assignment/closure, audited incident transitions, resolution/postmortem fields, notification scope/severity filters, retry history, and dead-letter handling.
- Added Owner/Admin/Operator/Viewer management, optional narrowing scopes, high-risk reauthentication, last-Owner protection, password rotation, and session-version revocation.
- Added reversible migration `0008_phase4_completion` and production startup guards requiring an explicit production gate and immutable commit.
- Added reversible migration `0009_agent_provenance`, side-effect-free Agent
  `version`/`--version` commands, authenticated heartbeat build metadata, Agent
  artifact manifests, and CycloneDX release metadata.
- Added reversible migration `0010_identity_recovery`, server-side user sessions,
  forced first-login password/TOTP/recovery-code setup, hash-only one-time recovery
  codes, audited session revocation, and transaction-locked last-Owner protections.
- Added bilingual Phase 4 workflows plus security, observation, production-gate, Staging/rollback, Komari coexistence, disk migration, and Nezha 2.3.0 comparison documentation.

### Changed

- Rebuilt Approval Center around semantic light/dark surfaces, compact filters,
  productized risk/Dry Run/rollback presentation, list-first tablet/mobile navigation,
  and a sticky audited decision bar.
- Validated UI V3 on real authenticated Staging at fixed commit
  `8722fabd28b3c6127fdfb8e2c630ed8fa94e5cfa`: median FCP 416 ms,
  LCP 580 ms and decision-data readiness 1.638 s across three cold runs,
  with 12 requests, zero long tasks, zero serious/critical axe findings,
  and successful Telegram warning/recovery delivery. Production remains
  `NO-GO`.
- Replaced the heavyweight Overview startup path with a minimal bootstrap followed by
  independently loaded current resource values; full metrics, Topology, Audit and raw
  evidence no longer block the first decision view.
- Replaced Services card/raw-output walls and Incidents black selected rows with
  structured comparison tables, localized semantic states, high-contrast selection,
  product names, controlled evidence viewers and decision-focused drawers.
- Reworked Overview, Services, Alerts, Incidents, Approvals, and Settings around structured actions instead of raw operational data.
- Added API pagination to fleet/history collections, GET request deduplication, and request cancellation support without increasing Agent sampling frequency.
- Made the deduplicated GET cleanup Promise the caller-visible Promise so an
  expected anonymous `/auth/me` `401` no longer emits an unhandled rejection;
  other client and server failures still propagate.
- Kept the dashboard authenticated and excluded the cancelled anonymous-read-only experiment.
- Added immutable OCI version/revision/created/source labels to every first-party
  container image and CI enforcement for those labels.

### Security

- High-risk approval and conditional approval now require server-side password
  reauthentication plus explicit rollback confirmation; conditional decisions and
  requests for changes never dispatch Agent tasks.
- Redact plain, JSON and NDJSON service evidence before returning it to the browser;
  evidence remains authenticated, escaped, collapsed by default, and downloadable only
  as the already-redacted representation.
- Authentication now rejects JWTs without a live, unexpired, unrevoked server Session
  row; password and authorization changes invalidate older sessions.
- TOTP confirmation rejects time-step replay, and recovery-code login is rate-limited,
  single-use, hash-only, and audited without recording the code.
- Explicit scopes now narrow role permissions at the API for separate read/write resources.
- Notification routing enforces event-scope and severity filters before enqueueing.
- Settings expose Secret configuration state and source only, never Secret values.
- Agent version commands exit before configuration loading and main-loop startup,
  preventing version probes from creating heartbeats or duplicate metrics.
- Added a reusable, fail-closed root-owned Secret-file reader and CI regression
  matrix for newline/no-newline files, ownership, permissions, symlinks, NUL
  bytes, empty values, invalid calls, and mid-read file replacement.

### Known limitations

- Current CRL handshake revalidation, off-site isolated restore, two real notification channels, larger multi-VPS validation, cross-cloud recovery, Staging rollback, accessibility/visual evidence, and 24-hour/7-day observation remain gates.
- Production remains `NO-GO`; historical RPO/RTO values are not presented as current measurements.

## [0.3.0-alpha.1] - 2026-07-23

### English

- Added English and Simplified Chinese Dashboard resources with browser-language detection, an explicit persisted selector, and localized dates, numbers, durations, statuses, errors, loading, empty, offline, and permission states.
- Added paired English and Simplified Chinese core documentation and Dashboard screenshots built from fictional data.
- Added host-bound CSR bootstrap, locally generated Agent private keys, bounded certificate renewal with atomic identity generation switching, and controlled monotonic CRL publication.
- Added Phase 4C bilingual staging and Nezha 2.3.0 benchmark documents. Runtime acceptance remains blocked or pending where real evidence is unavailable.
- Validated two real staging Agents through CSR bootstrap, renewal, revocation, CRL enforcement, eight service checks, alert recovery, approval-separated repair, exact task replay idempotency, and TTL rejection.
- Preserved post-repair verification steps when an approved runbook is converted into signed Agent tasks.

### 简体中文

- 使用两台真实 staging Agent 验证 CSR 接入、续签、吊销、CRL 拦截、八项服务检查、告警恢复、职责分离审批修复、任务重放幂等和 TTL 拒绝。
- 修复审批通过后丢失 runbook 复检步骤的问题，确保修复操作和 postcheck 都转换为签名 Agent 任务。

- 新增 English / 简体中文 Dashboard 资源，支持浏览器语言检测、手动选择持久化，以及日期、数字、时长、状态、错误、加载、空数据、断网和权限状态本地化。
- 新增成对的 English / 简体中文核心文档，以及使用虚构数据生成的 Dashboard 截图。
- 新增主机绑定 CSR Bootstrap、Agent 本地生成私钥、带原子身份代际切换的受限证书续签，以及受控、单调递增的 CRL 发布流程。
- 新增 Phase 4C 双语 staging 和哪吒 2.3.0 基准文档；没有真实证据的运行时验收继续明确标记为阻塞或 Pending。

## [0.1.0-alpha.1] - 2026-07-22

### Added

- Initial public Developer Preview of Controller, Web, PostgreSQL, and Linux Agent.
- TLS 1.3 mutual authentication for Agent ingress, RBAC, TOTP, CSRF, login limiting, task signatures, nonce replay defense, approvals, and auditing.
- Host heartbeat, resource metrics, offline queue, operations overview, diagnostics, recovery workflows, and Restic S3-compatible backups.
- Generic Docker Compose bootstrap, secure administrator creation, Agent installation docs, CI, checksums, and release SBOM generation where supported.

### Known limitations

- No production support commitment or stable upgrade compatibility yet.
- Alert delivery, broad service monitoring, automated repair approval, cross-cloud rebuild, and sustained large-fleet validation remain incomplete.
