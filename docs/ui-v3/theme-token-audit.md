# UI V3 Theme Token Audit

Status: implemented; automated verification pending final Staging capture

Audit date: 2026-07-27

## Design review source

This review applies the community `apple-design` Skill from
[`emilkowalski/skills`](https://github.com/emilkowalski/skills). It is not
Apple software or an official Apple specification bundle.

- Default branch: `main`
- Fixed source commit: `70744e3816f1d93eafb697161a8b880a7384c5ff`
- License: MIT, Copyright 2026 Emil Kowalski
- Source file: `skills/apple-design/SKILL.md`
- Skill SHA-256: `DA9581408C2B37A49565A9C7E32F26763F78B581C7E802DFA2357738E43BA7D5`
- Scripts in the Skill: none
- Scripts executed from the source repository: none
- Network, environment-variable, Secret, system-file, or automatic-install
  behavior in the Skill: none
- Installation result: `READ DIRECTLY`. The project-scoped
  `npx skills@latest add` attempt failed when its temporary GitHub clone
  connection was reset. No mirror or similarly named repository was used.

Applied principles: clear hierarchy; content/action proximity; restrained,
interruptible feedback; progressive disclosure; semantic materials; stable
spatial mapping; reduced motion; reasonable information density and targets.

## Root cause

The Staging document correctly had `data-theme="light"`; there was no observed
SSR/hydration theme mismatch. Approval Center was a dark-first legacy component:

- `.approval-list` hard-coded `#0e1115`.
- Unselected rows were transparent and inherited light-theme dark text.
- Selected rows used `var(--surface)`, causing an abrupt dark-to-white reversal.
- `.risk-banner` hard-coded `#1b1811`.
- Detail values and recovery text retained colors intended for dark surfaces.
- The light override changed a recovery background without consistently
  changing descendant foregrounds.
- The view directly rendered arbitrary database parameter/impact JSON.

The list did not directly reuse an Evidence Viewer class, but repeated the same
dark-terminal material assumptions. CSS specificity was not the primary cause;
the root was legacy hard-coded materials plus missing semantic presentation DTOs.

## Before / After / Why

| Component | Before | After | Why | Test |
|---|---|---|---|---|
| Approval list surface | Fixed `#0e1115` | `--surface-2` / `--panel` | One page must not look like two themes | Computed light/dark surface check |
| Unselected row | Transparent over dark list | Explicit semantic surface/text | Readability cannot depend on inheritance | Axe WCAG AA |
| Selected row | White/black reversal | Light accent surface and 3 px rail | Calm, continuous selection feedback | `aria-selected`, contrast |
| Risk presentation | Near-black banner | Low-chroma risk callout | Color carries meaning without becoming structure | No black background; Axe |
| Risk labels | Bare `L2` / `L3` | Localized low/moderate/high/critical labels | Operators should not decode policy shorthand | Risk matrix fixtures |
| List structure | Wide, low-density stack | Compact action/target/requester/time/status/risk rows | Comparison becomes immediate | Desktop/tablet/mobile |
| Approval title | Raw action identifier | Localized product name | Technical keys are not primary content | i18n tests |
| Detail order | Database field order | Risk, impact, steps, Dry Run, rollback, timeline, evidence | Matches decision order | Semantic section checks |
| UUID | Primary eyebrow | Removed from primary presentation | Identifiers are technical metadata | UUID absence regression |
| Raw values | Dash, `true`, `null` | Productized labels or omitted unavailable facts | Reduce interpretation cost | Raw-marker regression |
| Parameters | JSON open by default | Explicit server DTO; redacted evidence on demand | Progressive disclosure and least exposure | Request-count test |
| Dry Run | Raw boolean | Dedicated availability/result/action section | Availability must be actionable | Available/unavailable fixtures |
| Rollback | Pale strip and raw runbook phrase | Recovery reference, steps and explicit confirmation | High-risk action needs recovery context | With/without recovery tests |
| Timeline | Absent | Actor/time/outcome state flow | State changes remain legible | Lifecycle fixtures |
| Decision actions | Small trailing buttons | Sticky decision bar and native modal | Controls remain near consequences | Permission/focus tests |
| 768 px | Compressed columns | List-first, full-width detail | Preserve reading width | 768 visual test |
| 390 px | List plus long detail | Single-column list/detail flow | Avoid squeezed desktop layout | No-overflow test |
| Raw evidence | Small JSON box | Labeled viewer with search, lines, copy and full screen | Technical evidence stays available without dominating | Lazy-load/Axe test |
| Motion | Generic transitions | Restrained feedback; reduced-motion override | Professional UI should remain interruptible | Reduced-motion test |

## Global route audit

Scope: Overview, Services, Incidents, Approvals, Hosts, Alerts, Repairs,
Backup/Recovery, Security, Users, Agents, Notifications, Settings and Audit.

The static scan checks hard-coded exact black (`#000`, `#111`,
`background:black`), ordinary-content `color:white`, utility black classes and
`transition: all`. The browser matrix checks light/dark computed surfaces,
foreground contrast, horizontal overflow, page/console errors, serious or
critical Axe findings, unnamed controls and reduced-motion behavior.

No exact-black pattern remains in the scanned Vue/CSS sources. Dark materials
remain legitimate only for the dark theme, scrims, and explicitly labeled code
or evidence surfaces. Shared semantic theme tokens continue to be validated by
the route-wide Playwright suite.
