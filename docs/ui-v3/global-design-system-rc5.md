# UI V3 RC5 global design system

RC5 replaces page-local dark-first styling with a shared semantic system for the application
shell, repeated records, selection, domain labels, evidence, and responsive details. This is an
operations-console system, not a macOS imitation. It uses the community `apple-design` skill from
`emilkowalski/skills` at commit `70744e3816f1d93eafb697161a8b880a7384c5ff`, together with the
project-local `vps-guardian-product-ui` skill.

## Skill application record

| Skill rule | Current problem | Design decision | Implementation location | Acceptance evidence |
| --- | --- | --- | --- | --- |
| Response and feedback must be immediate | Rows changed to an unrelated dark surface on hover or expansion | Default, hover, selected, selected-hover, focus, and disabled are independent states | RC5 token layer and shared DataTable | Prototype computed-style gate and keyboard selection |
| Familiarity and spatial consistency | Hosts expanded in place into a large terminal-like block while Audit had hover but no selection model | Comparable records select consistently and open the same right-side Detail Drawer | Shared DataTable and Detail Drawer | Hosts/Audit 1366 selected screenshots |
| Simplicity is not hiding context | `no data`, `never`, raw IDs, and raw enums forced operators to infer meaning | Human state and reason appear in the record; raw evidence moves under closed technical details | Presentation Registry and domain presentation DTOs | Prototype main-table raw-value gate |
| Content and action should remain adjacent | Host actions appeared only inside an oversized expanded row | Safe common action remains in-row; full context and next action live in the Drawer | DataTable row action and domain Drawer slots | Hosts Drawer screenshot |
| Progressive disclosure | Audit main rows exposed action codes, UUID fragments, and internal IPs | Main list receives product labels; code, IDs, and internal addresses are secondary technical evidence | Audit presentation DTO and evidence section | Audit list and Drawer screenshots |
| Motion must be restrained and interruptible | Legacy CSS mixed unrelated transitions and permanent visual weight | Only opacity/transform, 120–200 ms, no bounce, no `transition: all`, reduced-motion path | RC5 interaction tokens and Drawer | Static CSS scan and reduced-motion browser test |
| Product structure must answer what, why, when, owner, next action | Generic tables showed persistence fields rather than decisions | Each primary record defines identity, state, reason, evidence time, owner/source, and next action | DataTable contracts and Presentation Registry | Page-by-page audit and fixtures |
| Technical identifiers never displace the title | Komari UUIDs and actor UUID fragments were primary copy | Human labels lead; technical identifiers live in secondary copy or closed details | ResourceIdentity and domain DTOs | Raw UUID browser gate |
| Empty, stale, disabled, unsupported, and failed are distinct | Hosts collapsed all missing evidence into `no data` or `never` | Typed presentation states include explanation and suggested next action | Host presentation DTO and StateNotice | Host state unit/browser matrix |
| Mobile is a different layout, not a squeezed table | Existing wide records were clipped or depended on page overflow | Semantic desktop table converts to compact records, filter controls move into a Sheet, Drawer becomes full screen | Shared DataTable/FilterBar/DetailDrawer | 390 screenshots and overflow assertion |

## Semantic tokens

The following public tokens are required in both light and dark themes:

- surfaces: `canvas`, `surface`, `surface-raised`, `surface-subtle`, `surface-hover`,
  `surface-selected`, `surface-selected-hover`, `surface-disabled`, `surface-code`,
  `surface-sidebar`, `surface-sidebar-selected`;
- text: `text-primary`, `text-secondary`, `text-tertiary`, `text-disabled`,
  `text-on-accent`, `text-on-critical`;
- boundaries: `border-default`, `border-subtle`, `border-selected`, `focus-ring`;
- meaning: `accent`, `healthy`, `warning`, `critical`, `info`, `neutral`.

`surface-code` is legal only inside evidence, terminal, code, and log viewers. Main content,
navigation selection, table selection, hover, warning, and severity may not consume it.

## Shared component contract

### App Shell

- Light theme uses a light neutral sidebar; dark theme uses adjacent dark surfaces rather than
  pure black.
- The selected route uses `surface-sidebar-selected`, a 3 px accent boundary, readable text, and
  `aria-current="page"`.
- The top bar exposes `Staging`, the compact RC label, and `Production not deployed`. Full version,
  Git SHA, and image identity move to a system-information popover.
- Account, theme, locale, help, and sign-out remain predictable and keyboard accessible.

### DataTable

- Native `table`, `thead`, `tbody`, `th`, and `td` semantics on desktop.
- Typed columns, sortable headers with `aria-sort`, bounded pagination, column visibility, loading,
  empty, and scoped error states.
- Rows support default, hover, selected, selected-hover, focus, disabled, warning, and critical
  without full-row severity fills.
- Selection uses `surface-selected`, a 3 px `border-selected` inset indicator, `text-primary`, and
  `aria-selected`.
- At 390 px, the same data becomes compact records with visible field labels and no horizontal page
  overflow.
- Hosts, Services, Alerts, Incidents, Approvals, Users, Agents, Notifications, Audit, Backup
  history, and Account Security events mount the same component. Decision and evidence detail may
  remain domain-specific, but the tabular state machine may not.
- Sorting, URL-backed filters, and column selection are composed by the owning route through the
  typed header slot; sortable headers expose `aria-sort`. The component owns table semantics,
  density, selection/focus behavior, bounded pagination, sticky headers, loading/empty/error
  states, optional virtualization mode, and responsive record conversion.

### Presentation Registry

The registry maps backend action, resource, result, severity, status, host-management, approval,
and notification values to:

- localized primary label;
- semantic tone;
- optional explanation;
- safe unknown fallback.

Unknown values render `Unknown action`, `Unknown resource`, or `Unknown status`; the original value
may appear only in technical details.

### Detail Drawer

- Opens from the current row and restores focus to it.
- Uses consistent heading, status, summary, key facts, activity/changes, related records, and
  closed technical evidence.
- Escape and overlay close are supported. At mobile width it uses the full viewport.
- No security decision is made by the Drawer; all mutations continue through authenticated backend
  authorization and state checks.

## Prototype gate

The isolated RC5 prototype passed after two rejected iterations:

1. rejected for tertiary-text, status-label, and dark-theme primary-button contrast;
2. rejected because the Audit Drawer retained Host facts after changing context;
3. accepted after token and semantic corrections.

Final gate evidence:

- light selected-row contrast: `14.23:1`;
- dark selected-row contrast: `10.85:1`;
- no near-black selection;
- no primary dotted action, snake case, raw boolean/null, or internal container IP;
- no 390 px horizontal overflow;
- nine tested scenes with zero serious or critical Axe violations.

## Implementation gate evidence

- All eleven required tabular surfaces mount `DataTable.vue`.
- Hosts is bounded to 200 presentation rows per request and paginates 50 rows at a time; it never
  downloads host history for the index.
- Audit fetches at most 100 presentation rows per page. Technical evidence is requested only when
  the operator expands Technical evidence; export accepts the active product filters and remains
  server-authorized, redacted, bounded, audited, and protected against CSV formula injection.
  Actor/resource identifiers, IP addresses, and change evidence are excluded from the list DTO and
  appear only in the explicitly requested, admin-only evidence DTO.
- A 390 px compact-record test and a 683 CSS-pixel 200%-zoom-equivalent reflow test assert no
  document-level horizontal overflow.
- Local post-fix Lighthouse on the signed-out route: Performance 100, Accessibility 100,
  FCP 425 ms, LCP 492 ms, CLS 0, and TBT 0. Best Practices remains 96 because the expected,
  handled anonymous `/auth/me` response is HTTP 401; this security behavior is not weakened for
  a synthetic score.
- Backend: 328 tests collected, 310 passed, 18 environment-specific/manual tests skipped; Ruff
  and mypy are clean. Frontend: 55 Vitest tests and 29 Playwright scenarios pass.
