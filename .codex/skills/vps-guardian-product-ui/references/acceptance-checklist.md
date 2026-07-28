# Product UI acceptance checklist

## Audit evidence

- Record the exact route, viewport, theme, locale, authenticated state, source SHA, runtime SHA,
  timestamp, cache mode, and run number.
- Capture Before screenshots before code changes.
- Record HAR, trace, Lighthouse, coverage, bundle composition, request waterfall, long tasks, API
  timings, and database timings when performance is in scope.
- Use at least three runs and retain median and worst values.

## Product structure

- The first viewport identifies health, active risk, stale evidence, ownership, and next action.
- Repeated homogeneous records use a table or compact list rather than a card wall.
- Details, timelines, configuration, audit, and raw evidence use progressive disclosure.
- Empty results show active filters and a clear-filter action.
- Technical identifiers never displace the human-readable title.

## Navigation and shell

- Selected text is visible on every route and has `aria-current="page"`.
- Selection uses a light accent surface, a boundary indicator, readable text, and a focus ring.
- Desktop content and navigation do not create competing scroll areas.
- Mobile navigation locks background scroll, closes with Escape or the overlay, traps focus, and
  restores focus to the trigger.
- Account, session, locale, theme, and sign-out live in one user menu; help and API docs live in
  help.

## Status and content

- Healthy, warning, critical, information, neutral, stale, disabled, no-data, unsupported, parse
  failure, and execution failure have distinct labels and explanations.
- Empty exception collections are healthy, not failed.
- Status never depends on color alone and pure black is not used for selection or severity.
- Chinese routes do not expose unapproved English sentences, `[object Object]`, `undefined`,
  `null`, or raw backend errors.
- Timestamps show a compact local form, a full timezone tooltip, and meaningful relative age.

## Loading and errors

- App Shell and page title render without waiting for page data.
- Skeleton geometry matches final content.
- Empty, error, stale, and loading states are different.
- Non-critical module failure degrades locally and has a scoped retry.
- Authentication and dashboard bootstrap are single-flight.
- Initial Overview does not fetch full topology, audit, incident history, or long-range metrics.
- Requests abort on route leave and background polling slows or stops when hidden.

## Accessibility and responsive layout

- Keyboard traversal, focus order, focus visibility, accessible names, semantic tables, Dialog and
  Drawer traps, Escape handling, and trigger focus restoration pass.
- Selection, warning, critical, muted text, evidence viewers, and dark mode meet contrast goals.
- Reduced motion removes spatial or elastic transitions without removing status feedback.
- At 390px the page has no horizontal overflow, filters move into a Sheet, tables become compact
  records, and detail Drawers use the viewport.
- At 768px only core table fields remain and navigation can collapse.

## Performance and release gate

- Measure DNS, TCP, TLS, TTFB, FCP, LCP, CLS, load, interactive readiness, critical-data readiness,
  request count, bytes, JavaScript execution, and long tasks.
- Attribute delays to network, server, transfer, JavaScript, and rendering.
- Report initial JS/CSS gzip sizes and the twenty largest bundle modules.
- Confirm no source maps, credentials, raw evidence, or secrets reach the public client bundle.
- Require rollback inputs, fixed source/image identities, CI, migrations, and Staging backups before
  deployment.
- Product approval requires manual screenshot review; green automation alone is insufficient.
