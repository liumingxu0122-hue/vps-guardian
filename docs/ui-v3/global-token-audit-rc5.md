# RC5 global token and shared-state audit

Source baseline: `ed192cd8c86696225393d90859bd4420504ec529`, real authenticated Staging RC4,
Chinese locale, light and dark themes. Before evidence is stored outside Git under
`outputs/ui-v3-rc5-staging-before-2026-07-27T162944-661Z`.

## Root cause

`web/src/styles.css` starts with a dark-only root palette and later adds a light-theme variable
override. Several shared and page-level states bypass those variables:

- `.table-row:hover { background: #11151a; }`;
- `.host-item.expanded { background: #0e1216; }`;
- `.host-summary:hover { background: #11151a; }`;
- `.incident-row:hover, .incident-row.selected { background: #11161a; }`;
- legacy detail and approval containers also use `#0e1115`.

The light-theme block changes `--surface` and text variables but cannot alter hard-coded dark
backgrounds. Text continues to resolve from the light palette, producing dark text on dark rows.
Audit has no selection state at all; the reported selected row is its shared dark hover state.
Hosts combines dark hover and dark expanded states, creating the larger black region.

`styles.css` and `ui-v3.css` also define overlapping token vocabularies and are imported together.
Some newer routes consume the `proto-*` system while older routes consume legacy global classes.
This split is why one route can pass while another repeats the same failure.

## Audit matrix

| Component | Before | RC5 decision | Why | Test |
| --- | --- | --- | --- | --- |
| Root theme | Dark-first `--bg`, `--surface`, `--text`; later light override | One semantic light definition and one explicit dark definition | Prevent inherited theme ambiguity | Token completeness test |
| Ordinary canvas | `#0b0d10` default plus later light override | `canvas` | Page surface must be intentional | Computed style light/dark |
| Sidebar | Permanent `#0e1115` in light and dark | `surface-sidebar`, theme-specific | Reduce permanent visual weight | All-route navigation screenshots |
| Nav selected | Hard-coded dark green-black | `surface-sidebar-selected` + accent boundary | Selection remains readable and predictable | `aria-current` and contrast |
| Generic row hover | Hard-coded `#11151a` | `surface-hover` | Hover must respect theme | Pointer-fine browser state test |
| Host expanded | Hard-coded `#0e1216` | Selected row plus Detail Drawer | Expansion must not become a terminal panel | Hosts selected screenshot |
| Incident selected | Hard-coded `#11161a` | Shared selected state | Same semantics on every record list | Incidents regression |
| Approval selected | Page-specific selected palette | Shared selected state with Approval detail behavior retained | Avoid future divergence | Approvals regression |
| Audit row | Hover only, no selection semantics | DataTable row selection and Drawer | Keyboard and screen readers need real state | Audit selection test |
| Evidence | Ordinary panel tokens mixed with evidence surface | `surface-code` scoped inside evidence viewer | Dark evidence must not leak | Selector-scope test |
| Status badges | Multiple components and raw backend status inputs | Presentation Registry tone + one StatusBadge | Stable cross-page meaning | Registry matrix |
| Disabled | Page-local opacity and color | `surface-disabled`, `text-disabled`, explicit text | Disabled must not look like missing data | Component state story |
| Focus | Mixed outline and color-only selection | `focus-ring`, non-color outline | WCAG and keyboard operation | focus-visible browser test |
| Mobile records | Desktop grids squeezed or hidden | DataTable compact-record fallback | Prevent overflow and lost meaning | 390 px test |
| Motion | Page-local transitions | 120–200 ms transform/opacity, reduced-motion | Feedback without performance cost | CSS lint and media emulation |

## Forbidden-value audit

RC5 CI must fail when main product surfaces introduce:

- `#000`, `#111`, `black`, or near-black hard-coded backgrounds outside allowlisted evidence/code
  selectors;
- `transition: all`;
- raw dotted action codes, snake-case enums, `[object Object]`, `undefined`, raw
  `true/false/null`, UUID-only titles, or private/container IPs as primary content;
- selected states without `aria-selected`, readable text, accent boundary, and focus visibility.

The audit scans generated browser text in both locales and computed styles in both themes; a
snapshot update cannot waive these checks.
