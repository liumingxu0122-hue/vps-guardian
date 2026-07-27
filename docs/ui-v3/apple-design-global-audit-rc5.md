# RC5 Apple Design and Product UI global audit

Baseline: real Staging RC4 at `ed192cd8c86696225393d90859bd4420504ec529`, authenticated
Owner, Chinese locale. Evidence includes 64 screenshots, three cold runs, sanitized HAR, Chrome
trace, coverage, and browser-error records.

| Page | Skill rule | Before problem | Decision | Implementation | Evidence |
| --- | --- | --- | --- | --- | --- |
| `/overview` | Content priority | Healthy/risk data is useful, but the permanent dark sidebar and full RC string dominate; gate text includes raw English | Keep operational summary; migrate shell and presentation labels | RC5 App Shell and registry | 1366 light/dark Before; shell prototype |
| `/hosts` | Understanding, product states | Dark hover/expanded row, no headers, Komari IDs/tags lead, `no data` and `never` hide cause | Shared DataTable, six-state summary, management/heartbeat presentations, Drawer | Host presentation DTO + DataTable | selected-row and 390 Before/After |
| `/services` | Comparable records | New table is stronger but has page-specific selection/status logic | Migrate columns and selection to shared DataTable; preserve lazy evidence | DataTable adapter + registry | light/dark and detail regression |
| `/topology` | Progressive disclosure | Status values are passed directly to the legacy badge; technical topology can dominate at small widths | Productized node state, semantic legend, responsive detail | Registry + topology detail | route screenshots |
| `/alerts` | Specific labels | Severity is titleized and assignee falls back to an ID fragment | Registry labels and actor identity presentation | Alert DTO adapter/DataTable | raw-value scan |
| `/incidents` | Spatial consistency | New Drawer exists but selection uses a separate table implementation | Retain IA; move selection/status primitives to shared system | DataTable migration | selected light/dark regression |
| `/repairs` | Responsibility | Risk and approval fields still mix raw values with product labels | Registry mapping; impact and authorization remain explicit | Repair presentation adapter | light/dark screenshots |
| `/approvals` | Progressive disclosure | RC4 fixes the primary defect but has its own queue/selection implementation | Preserve decision-ordered detail and security; adopt global tokens/registry | Approval regression adapter | 1366/768/390 regression |
| `/backup` | Wayfinding | Route does not exist and redirects to Overview | Add a real alias or nav-safe canonical path to recovery history | Router alias to protected recovery route | final-path assertion |
| `/recovery` | Technical IDs secondary | Snapshot/checksum fragments and fallback host IDs are prominent | Product recovery title first; identifiers in technical detail | Recovery presentation adapter | raw-ID scan |
| `/account-security` | Familiarity | Session and audit events expose ID fragments and raw action/outcome values | Registry labels and named session/device presentation | Security event registry | authenticated regression |
| `/security` | Understanding | Generic object iteration titleizes keys and passes raw strings to StatusBadge | Explicit whitelist presentation DTO/registry | Security presentation component | unknown-value tests |
| `/users` | Agency | User table and session rows use different table systems; session IDs become titles | Shared DataTable; account identity leads; session ID secondary | Users DataTable adapter | role/session matrix |
| `/agents` | Technical IDs secondary | Selected Agent ID fragment is the detail title; raw identity state is passed through | Host/Agent display identity and registry state; IDs under technical details | Agent presentation adapter | identity-state tests |
| `/notifications` | Specific labels | Channel kind/event scopes are raw and delivery fallback is an ID fragment | Notification registry and human event labels | Notifications DataTable adapter | event/result tests |
| `/audit` | Understanding and progressive disclosure | Generic DB viewer: dotted actions, raw resource enums, actor IDs, internal IPs, raw outcomes, no detail flow | Explicit presentation DTO, shared DataTable, paged filters, security Drawer | Audit presentation API + DataTable | hover Before; list/Drawer prototype |
| `/settings` | Purpose | Feature/secret/risk values are produced by generic titleization | Explicit safe registry entries and unknown fallback | Settings presentation registry | raw-enum CI |

## Per-route acceptance ledger

This ledger records every required audit dimension rather than treating a screenshot as proof of
the whole route.

| Route | Visual | Information architecture | Technical fields | State semantics | Responsive | Accessibility | Performance | Shared system / disposition |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `/overview` | Dark sidebar dominated RC4 | Release text competed with health | Full RC string led the header | Mixed gate labels | Dense cards at 390 | Shell focus order retained | Bootstrap already bounded | RC5 Shell + registry; fixed |
| `/hosts` | Near-black expanded/selected row | No headings or stable comparison | Komari tags and identifiers led | No-data/never unexplained | Wide row clipped | No row selection semantics | History risked eager loading | DataTable + explicit DTO + Drawer; fixed |
| `/services` | Page-specific selected state | Evidence mixed with summary | Check kinds were raw | Check states diverged | 11 columns squeezed | Separate keyboard model | Evidence already lazy | DataTable + registry; fixed |
| `/topology` | Technical graph dominated | Status lacked explanation | Node kinds were raw | Badge vocabulary diverged | Graph crowded small width | Legend needed text | Bounded summary retained | Registry + responsive detail; fixed |
| `/alerts` | Card list lacked comparison | Actions obscured alert facts | Assignee could be an ID | Severity was titleized | Actions wrapped unpredictably | Cards lacked table semantics | Two bounded requests | DataTable + registry; fixed |
| `/incidents` | Separate selected palette | Useful Drawer, inconsistent list | Source values leaked | Status/severity local | Desktop table squeezed | Selection keyboard local | Detail remains local/lazy | DataTable + registry; fixed |
| `/repairs` | Risk fields looked generic | Authorization needed priority | Repair enums leaked | Risk vocabulary differed | Existing responsive stack | Existing focus retained | No new requests | RC5 tokens + registry; fixed |
| `/approvals` | Page-local queue selection | Decision flow was strong | Action names could be raw | Risk/status local | Master/detail needed reflow | Listbox differed from tables | Detail/evidence already lazy | DataTable + secure detail; fixed |
| `/backup` | Route silently redirected | Navigation target absent | Snapshot fragments led | Verified/unknown mixed | Cards were inconsistent | No table semantics | Existing bounded endpoint | Protected alias + DataTable; fixed |
| `/account-security` | Control rows differed | Sessions/events lacked columns | Session fragments led | Raw audit outcome | Rows compressed at 390 | Generic div rows | Existing bounded endpoints | Two compact DataTables + registry; fixed |
| `/security` | Generic settings appearance | Controls lacked product labels | Object keys were raw | Boolean/raw status | Long values wrapped poorly | Labels were implicit | Existing summary retained | Explicit registry presentation; fixed |
| `/users` | Legacy row system | Sessions competed with identity | Session ID became title | Role/status inconsistent | Wide row overflow risk | Div rows lacked table semantics | Existing bounded endpoint | DataTable + role/status labels; fixed |
| `/agents` | Split list used raw identity | Host identity did not lead | Agent ID/serial led | Identity state raw | Split view squeezed | Button list differed from table | Identity detail remains on demand | DataTable + human host identity; fixed |
| `/notifications` | Delivery rows differed | Channel/result hierarchy weak | Event scopes/IDs leaked | Channel/result enums raw | Rows overflowed | Legacy div table | Existing bounded endpoint | DataTable + notification registry; fixed |
| `/audit` | Near-black hover looked selected | Database event viewer, no flow | Codes, UUIDs, internal IP led | Result/source raw | Table not mobile-safe | No selection/Drawer semantics | Evidence and history eager-risk | Explicit DTO + DataTable + on-demand evidence; fixed |
| `/settings` | Generic catalog | Effective values lacked hierarchy | Feature/secret keys raw | Boolean/risk raw | Long keys and values crowded | Generic rows | Existing endpoint retained | Explicit registry + semantic tokens; fixed |

All fixes remain subject to the real-Staging gate. “Fixed” here means implemented and locally
verified; it does not claim human acceptance or Production approval.

## Global implementation gate

Every route must consume the RC5 token layer and shared status/presentation vocabulary. Hosts and
Audit are the priority migrations, but RC5 remains NO-GO until all routes above pass:

- light/dark selected-state readability;
- main-surface raw-value scan;
- 1366, 768, and 390 responsive checks;
- keyboard/focus/Drawer behavior;
- no serious or critical Axe findings;
- no significant bundle, request-count, FCP, LCP, CLS, or long-task regression.

Local implementation evidence at the RC5 candidate gate:

- Vitest: 55 passed;
- Playwright: 29 scenarios, including all eleven DataTable surfaces and a 683 CSS-pixel
  reflow check equivalent to a 1366 px viewport at 200% zoom;
- Axe: no serious or critical findings on the critical route and Drawer checks;
- Ruff and mypy: clean;
- pytest: 328 collected, 310 passed, 18 environment-specific/manual tests skipped;
- production build: route-split, largest generated JavaScript chunk 110.49 kB before gzip and
  largest page chunk 24.88 kB before gzip;
- npm audit, pip-audit, and Gitleaks: no findings at the recorded local gate.
