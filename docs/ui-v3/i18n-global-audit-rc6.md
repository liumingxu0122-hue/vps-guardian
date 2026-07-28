# RC6 complete i18n and runtime-language audit

Status: implementation candidate; Staging not yet deployed; Production `NO-GO`.

## Runtime contract

- Supported production locales are exactly `zh-CN` and `en-US`.
- Resolution order is `guardian_locale` preference cookie, browser language, then
  `zh-CN`. The preference cookie is non-authentication state, `SameSite=Lax`,
  `Path=/`, one-year `Max-Age`, and `Secure` on HTTPS.
- Switching is immediate and does not reload, navigate, clear filters, close the
  active route, or mutate authentication state.
- The Globe menu is anchored to its trigger, reports the current language, supports
  Arrow Up/Down, Home/End, Enter, Escape, outside click, and returns focus.
- Date, time, relative time, duration, byte, and number presentation uses `Intl`.
- Backend authentication/session failures expose stable codes and parameters; the
  browser maps those codes through locale resources rather than displaying raw
  server messages.

## Coverage

The key-parity test recursively compares both locale trees and rejects empty values.
Login, boot/restore errors, identity setup, Account Security, session/device fields,
step-up, shared DataTable states, App Shell, search, and language controls use shared
resources. Existing product routes remain covered by the cross-route Playwright
machine-value audit.

Technical identifiers that intentionally remain language-neutral include VPS
Guardian, Controller, Agent, TOTP, API, CPU, TLS, PostgreSQL, systemd, Docker, mTLS,
RBAC, CSRF, RPO/RTO, version strings, email addresses, opaque IDs, and protocol or
notification-channel names. They are product or standards vocabulary, not residual
English prose.

## Route and component audit

| Route | Component | English Leak | Translation Key | zh-CN | en-US | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `/login` | `LoginView` | Fixed: form labels, recovery-code help, remember-session option | `login.*`, `locale.*` | Complete | Complete | Vitest + Playwright deep link |
| `/identity-setup` | `IdentitySetupView` | Fixed: setup steps, errors, one-time-secret warnings | `identitySetup.*` | Complete | Complete | Playwright route audit |
| `/account-security` | `AccountSecurityView` | Fixed: headings, empty table, recovery, TOTP, session/device fields | `accountSecurity.*`, `common.*` | Complete | Complete | Vitest parity + Playwright |
| `/account-security` | `StepUpDialog` | Fixed: title, inputs, failure states, actions | `accountSecurity.stepUp*`, `errors.*` | Complete | Complete | Playwright step-up |
| all authenticated routes | `OperationsLayout` | Fixed: former ambiguous “中” control and shell labels | `locale.*`, `shell.*`, `nav.*` | Complete | Complete | Keyboard switch + route/query persistence |
| shared tables | `DataTable` | Fixed: “No matching records”, pagination, result counts | `common.noMatchingRecords`, `common.previous`, `common.next`, `common.pageOf` | Complete | Complete | Vitest parity + shared-table Playwright |
| shared drawers | `DetailDrawer` | Fixed: close control and accessible label | `common.close` | Complete | Complete | Axe + drawer tests |
| `/overview` | `OverviewView` | Audited; product terms only | `overview.*`, `status.*` | Complete | Complete | Cross-route audit |
| `/hosts` | `HostsView` | Audited; Agent/Komari and machine identifiers retained intentionally | `hosts.*` + Presentation Registry | Complete | Complete | 1366/390 Playwright |
| `/services` | `ServicesView` | Audited; HTTP/TCP/systemd/Docker identifiers retained intentionally | `services.*` + Presentation Registry | Complete | Complete | 1366/390 Playwright |
| `/topology` | `TopologyView` | Audited; Controller/Agent/PostgreSQL trust-boundary names retained | `topology.*` | Complete | Complete | Cross-route audit |
| `/alerts` | `AlertsView` | Fixed: filters, empty state, dialog and actions | `alerts.*`, `status.*` | Complete | Complete | Cross-route audit |
| `/incidents` | `IncidentsView` | Audited; Owner is product role terminology | `incidents.*` + Presentation Registry | Complete | Complete | 1366/390 Playwright |
| `/repairs` | `RepairsView` | No unapproved residual copy | `repairs.*` | Complete | Complete | Cross-route audit |
| `/approvals` | `ApprovalsView` | Fixed: decision, evidence and status vocabulary | `approvals.*` + Presentation Registry | Complete | Complete | desktop/mobile/a11y |
| `/backup` | `RecoveryView` | Fixed: recovery-point status and actions | `recovery.*` | Complete | Complete | Cross-route audit |
| `/security` | `SecurityView` | Technical security acronyms retained intentionally | `security.*`, `status.*` | Complete | Complete | Cross-route audit |
| `/users` | `UsersView` | Fixed: account/session management labels | `users.*`, `status.*` | Complete | Complete | Cross-route audit |
| `/agents` | `AgentsView` | Agent is retained as a product noun | `agents.*` + Presentation Registry | Complete | Complete | Cross-route audit |
| `/notifications` | `NotificationsView` | Channel protocol names retained intentionally | `notifications.*`, `status.*` | Complete | Complete | Cross-route audit |
| `/audit` | `AuditView` | Fixed: load state; raw codes restricted to collapsed technical evidence | `audit.*` + Presentation Registry | Complete | Complete | drawer + machine-value audit |
| `/settings` | `SettingsView` | Environment keys/protocol identifiers remain technical data | `settings.*` + Presentation Registry | Complete | Complete | Cross-route audit |
| restore/error shell | `App` | Fixed: restore state and Staging label | `app.*`, `errors.*` | Complete | Complete | Vitest auth lifecycle |

`web/src/prototype/UiV3Prototype.vue` is a non-routed design fixture and is excluded
from production route coverage. It is not bundled as a selectable product screen.

## Test-only pseudo locale

`pseudoLocalize()` provides the `en-XA`-equivalent test transformation: source text is
bracketed and vowels are expanded. A development-only `?__locale=en-XA` harness
registers it for Playwright; Vite removes that branch and emits no pseudo-locale
asset in the production build. It never appears in the language menu. Vitest checks
resource transformation, while Playwright checks 390 px layout and captures Overview,
Hosts, Audit, Approvals, Account Security, and Login evidence.

## Gates

- Vitest: matching keys, non-empty values, locale priority, unsupported-language
  fallback, pseudo-localization, and authentication request lifecycle.
- Playwright: runtime switch without reload, route/query preservation, keyboard
  selection/focus return, persistence after reload, deep-link login, stale Cookie,
  logout, 390 px reflow, shared table layout, accessibility, and product route audit.
- Real Staging screenshots and authenticated browser verification are mandatory
  before deployment acceptance; local mocks are not sufficient evidence.
