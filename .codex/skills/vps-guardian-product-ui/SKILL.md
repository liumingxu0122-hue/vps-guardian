---
name: vps-guardian-product-ui
description: Audit, prototype, implement, and validate a production-quality operations console for VPS Guardian. Use for UI or UX reviews, information-architecture changes, design-system work, status semantics, responsive layouts, accessibility, frontend loading performance, browser evidence, and product-quality gates in the Vue Web application.
---

# VPS Guardian Product UI

Build a calm, trustworthy infrastructure console that makes current risk and the next operator
action obvious. Preserve authentication, RBAC, audit, Agent, notification, backup, and production
deployment boundaries while changing presentation or data loading.

## Workflow

1. Establish the exact source, runtime, data, viewport, theme, language, and authentication state.
2. Capture the current UI before editing. Measure at least three runs for performance claims and
   retain the median and worst result.
3. Write concrete defects tied to a route, viewport, state, and observable evidence.
4. Define information priority and status meaning before writing components or CSS.
5. Create tokens and shared primitives before page-specific styling.
6. Prototype App Shell, Overview, Services, and Incidents with representative structured fixtures.
7. Render desktop, tablet, and 390px mobile screenshots in light and dark themes.
8. Review the prototype against `references/acceptance-checklist.md`. Do not continue if it still
   resembles a generic admin template or obscures operator decisions.
9. Connect real APIs with abortable, parallel, locally degradable loading. Keep authentication
   initialization single-flight.
10. Run unit, route, browser, accessibility, localization, bundle, and measured performance gates.
11. Deploy only to an explicitly authorized Staging target after rollback evidence exists.

## Information architecture

- Make every page answer: where am I, what needs attention, why, when did it change, and what can I
  safely do next?
- Put current health, scope, owner, evidence time, and next action before identifiers or raw data.
- Use compact lists and tables for comparable repeated records. Use cards only for a few
  heterogeneous summaries. Use a Drawer or dedicated route for details.
- Show raw JSON, logs, and command output only inside a closed-by-default evidence viewer.
- Keep technical IDs as secondary copy with copy affordances; never use them as the only title.
- Distinguish empty, loading, request failure, stale, no data, unsupported, and permission-denied
  states.

## Status semantics

- Define one typed status vocabulary and map backend states centrally.
- Use healthy, warning, critical, info, and neutral tokens consistently.
- Never infer failure from an empty exception set. Distinguish execution failure, monitored-object
  failure, no findings, parse failure, unsupported, disabled, and stale data.
- Pair color with text or an icon. Do not use pure black for selection, warning, or severity.
- Explain the reason and evidence time next to aggregate health. Historical test records must not
  silently dominate current health.

## Visual and interaction rules

- Use the platform system font stack and a 4px spacing foundation.
- Prefer restrained surfaces, strong typography, subtle borders, and one clear focus per page.
- Avoid card nesting, pill proliferation, large gradients, glass effects, neon, decorative motion,
  and heavy shadows.
- Keep motion between 120–200ms, interruptible when interactive, and limited to transform or
  opacity. Provide a reduced-motion path.
- Preserve visible labels for selected navigation items and expose `aria-current="page"`.
- Require explicit text, impact, and confirmation for destructive actions.

## Responsive and accessibility rules

- At 390px, use a navigation Drawer, prevent page-level horizontal overflow, convert tables to
  compact records, and make detail Drawers full-screen.
- At tablet widths, retain only core table columns and allow navigation collapse.
- Keep focus visible, order logical, and traps correct for Dialogs and Drawers. Support Escape,
  overlay close, restoration to the trigger, keyboard operation, semantic tables, accessible
  names, and screen-reader status text.
- Verify light/dark contrast for selection, warning, critical, muted text, and evidence viewers.
- Do not rely on color, hover, or pointer input alone.

## Performance rules

- Render App Shell before non-critical data. Request `/auth/me` once, then one lightweight
  dashboard bootstrap. Defer charts, topology, evidence viewers, long histories, and polling.
- Use route-level splitting, dynamic imports for heavy modules, request cancellation, visibility
  aware polling, and local error boundaries.
- Do not conceal latency with delayed requests, hidden data, fake fixtures in Staging, or
  indefinite skeletons.
- Default budgets: initial JS gzip at most 180 KB, CSS gzip at most 35 KB, first-screen transfer at
  most 400 KB, at most 20 requests, FCP at most 1.5s, LCP at most 2.5s, CLS at most 0.1, and
  critical data at most 3s. Change a budget only with measured evidence and an explicit reason.
- Attribute latency to network, server, transfer, JavaScript, and rendering. Record p50/p95 for
  relevant APIs and use Server-Timing where available.

## Evidence and safety

- Keep Before and After artifacts separate and label source SHA, runtime SHA, route, viewport,
  theme, language, run number, cache state, and timestamp.
- Treat a screenshot baseline as regression evidence, not product approval.
- Never store credentials, session state, host identifiers, private logs, or infrastructure
  details in Git.
- Never weaken authentication or authorization for measurement. Never deploy Production, change
  DNS, Gateway, Nginx, Komari, certificates, CRLs, Owners, TOTP, recovery codes, or backups unless
  separately authorized.
- Stop and retain evidence when a security boundary, data-integrity gate, or rollback prerequisite
  fails.
