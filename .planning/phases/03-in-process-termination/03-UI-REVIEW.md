# Phase 3 — UI Review

**Audited:** 2026-08-27
**Baseline:** `.planning/phases/03-in-process-termination/03-UI-SPEC.md` (locked design contract)
**Screenshots:** not captured — no dev server; this is a Go example whose HTTP server is only reachable through an in-process OpenVPN/netstack tunnel, not a local port. Audit performed against `site.go`, `pages.go`, `style.css`, and `site_test.go` (source + contract-test review).

**Scope note:** This is a deliberately minimal, 5-page, no-JS, no-framework proof-of-life demo for a developer audience. Scoring is proportionate to that scope — the bar is "does it hold to its own locked contract," not "does it look like a product marketing site."

---

## Pillar Scores

| Pillar | Score | Key Finding |
|--------|-------|-------------|
| 1. Copywriting | 4/4 | All locked strings (CTA, empty/error copy, nav labels) match the contract verbatim, enforced by tests. |
| 2. Visuals | 3/4 | `table-layout: fixed` with no column-width split risks uneven label/value column proportions on the status and headers tables. |
| 3. Color | 2/4 | `.echo-error`'s `border-left` uses `--color-accent`, which is outside the UI-SPEC's explicit accent reserved-for list ("nothing else uses `--color-accent`"). |
| 4. Typography | 3/4 | Table `<th>` combines 14px + 600 weight, a size/weight pairing not among the four declared type roles. |
| 5. Spacing | 4/4 | Every spacing value in `style.css` is a `var(--space-*)` token from the declared 8-point scale; no arbitrary values found. |
| 6. Experience Design | 4/4 | Empty/populated/error/backstop states are all implemented and unit-tested; synchronous rendering; no unhandled panics on malformed input. |

**Overall: 20/24**

---

## Top 3 Priority Fixes

1. **Accent color leaks outside its locked reserved-for list** (`examples/tunnelweb/site/style.css:234-240`, `.echo-error { border-left: 4px solid var(--color-accent); }`) — This is a direct written contract violation: UI-SPEC §Color states accent is reserved for nav links, the "Send echo" button, `:focus-visible` outlines, and the "tunnel: active" indicator, and explicitly says "nothing else uses `--color-accent`." An error state is not decorative-adjacent to a CTA; using the accent color here also risks visually implying the error box is "good"/actionable rather than a warning. **Fix:** change `.echo-error`'s border to `--color-border` or `--color-text`, keeping accent's 10% budget scoped to the four declared elements only.

2. **Status/headers table columns have no explicit width split under `table-layout: fixed`** (`examples/tunnelweb/site/style.css:153-159`) — With `table-layout: fixed` and no `<colgroup>` or first-row width hints, browsers default toward even column splitting. On the status page this puts a long label ("Client source port") against a short/wrapping mono value in oddly-proportioned cells; on the headers page it does the same for short header names against long values (`User-Agent`, `Cookie`). This can look visually unbalanced even though the `overflow`/`wrap` CSS rules technically prevent horizontal scroll. **Fix:** add a `<colgroup>` (e.g. `35%/65%` for name/value pairs) or set an explicit `width` on the first `<th>` of each table so the label column doesn't compete for space with wrapped values.

3. **`<th>` typography uses an undeclared size/weight pairing** (`examples/tunnelweb/site/style.css:169-172`, `th { font-weight: 600; font-size: var(--text-sm); }`) — UI-SPEC's Typography table locks exactly four role/size/weight combinations: Body (16/400), Label-meta (14/400), Heading (24/600), Display (32/600). 14px+600 is not one of them — it's a fifth de facto combination assembled from tokens that are each individually declared but never paired this way in the contract. This doesn't blow the "exactly 2 weights, exactly 4 sizes" *count* constraint, but it is a deviation from the *contract's own enumerated role table*, and a future page could keep stacking new pairings from the same token pool without ever technically violating the count rule. **Fix:** either add "Table header" as an explicit fifth role to the UI-SPEC (if this pairing is intentional and worth keeping), or drop `<th>` back to Label/meta's declared 14px/400 and rely on `<th>`'s native semantic weight/scope for emphasis instead of an extra bolded size.

---

## Detailed Findings

### Pillar 1: Copywriting (4/4)
- Nav labels ("Status", "About", "Echo test", "Headers") and their one-line descriptions match UI-SPEC §1's table exactly (`pages.go:44-48`, verified by `TestLandingPageStructure`).
- Echo-test CTA is exactly `"Send echo"` (`pages.go:363`, `TestEchoFormShape`).
- Empty-state heading `"Nothing to echo yet"` and body copy (`echoEmptyBodyCopy`, `pages.go:303`) match the Copywriting Contract verbatim, single-sourced as a constant shared between the template and test suite — good practice, avoids copy drift.
- Error copy `"Echo failed — the message was empty or too large. Type something under 4KB and try again."` matches verbatim (`pages.go:304`).
- Landing page states the "no TUN device"/"CAP_NET_ADMIN" core claim in plain language exactly as UI-SPEC §1 requires (`pages.go:99`, `TestLandingStatesTheCoreClaim`).
- No generic labels ("Submit", "Click Here", "OK") found anywhere in `pages.go`.
- No issues found. This pillar is a clean pass.

### Pillar 2: Visuals (3/4)
- Clear focal point on landing (`<h1>govpn tunnelweb</h1>` + single explanatory sentence + nav) — matches UI-SPEC §1.
- No icon-only controls exist anywhere (per spec, this scope has none), so the aria-label/tooltip pairing rule is moot — correctly not applicable.
- Visual hierarchy exists through the four declared sizes/weights (brand 24/600, h1 32/600, h2 24/600, body 16/400, nav-desc 14/400).
- **Issue (WARNING):** `table { table-layout: fixed; }` (`style.css:153-159`) with no `<colgroup>`/explicit column widths risks uneven label/value proportions on both the status definition-table and the headers table — see Priority Fix #2.
- **Note:** No responsive breakpoints or media queries exist anywhere in `style.css`. The header uses `flex-wrap: wrap` and nav uses `flex-wrap: wrap`, which provides some graceful degradation on narrow viewports, but this can't be visually confirmed without a live render (no dev server available for this project type). Given the audience (a developer glancing at a proof-of-life page, likely on desktop), this is proportionate and not scored as a defect, but flagged as an open risk since it was never visually verified.

### Pillar 3: Color (2/4)
- Accent (`--color-accent`) usage on nav links, the "Send echo" button, and the "tunnel: active" status text all match the reserved-for list exactly (`style.css:102-104`, `:222-232`, `:192-195`).
- `:focus-visible` outlines correctly use accent at 2px solid with 2px offset (`style.css:251-256`), matching Accessibility Basics.
- No hardcoded hex/rgb colors found outside the single `:root` token block — all page styles are built from custom properties, matching the Design Tokens delivery constraint.
- **Issue (BLOCKER-adjacent, contract violation):** `.echo-error { border-left: 4px solid var(--color-accent); ... }` (`style.css:234-240`) applies accent color to the error state, which UI-SPEC explicitly excludes ("Nothing else uses `--color-accent` — body text, headings, and table borders all use `--color-text`/`--color-border`"). This is the one clear, unambiguous divergence from the written contract found in this audit — see Priority Fix #1.

### Pillar 4: Typography (3/4)
- Exactly 4 sizes (`--text-sm` 14px, `--text-base` 16px, `--text-lg` 24px, `--text-xl` 32px) and exactly 2 weights (400, 600) are declared and used, matching the "exactly 2 weights, exactly 4 sizes" count rule.
- Monospace (`.mono`) correctly inherits its surrounding role's size and only changes font-family, not treated as a fifth role — matches UI-SPEC's explicit carve-out.
- Heading line-heights (1.2 for h1/h2) and body line-height (1.5, inherited from `html, body`) match the Typography table.
- **Issue (WARNING):** `th { font-weight: 600; font-size: var(--text-sm); }` (`style.css:169-172`) creates a 14px/600 pairing that isn't one of the four declared role combinations (Body 16/400, Label 14/400, Heading 24/600, Display 32/600) — see Priority Fix #3.

### Pillar 5: Spacing (4/4)
- Every spacing value used across `style.css` (header/nav/main/table/form/footer padding, margins, gaps) resolves to one of the declared `--space-*` tokens (`4/8/16/24/32/48/64`); no arbitrary pixel or rem values found anywhere.
- `--space-3xl` (64px) is declared and deliberately unused, exactly matching UI-SPEC's own note ("Not used on these small single-column pages — reserved token, no current usage").
- Spacing usage broadly matches the declared role-to-token mapping (e.g. `--space-sm` for table cell padding, `--space-lg`/`--space-xl` for section/layout padding, `--space-2xl` for main's top padding as the "page header to content gap").
- No issues found. This pillar is a clean pass.

### Pillar 6: Experience Design (4/4)
- Empty state (`/echo` GET): unfilled textarea with placeholder, no prior value shown, exact empty-state copy — implemented and tested (`TestEchoEmptyState`).
- Populated state (successful POST): shows `"You sent: {escaped value}"`, HTML-escaped via `html/template`'s contextual auto-escaping — verified against a literal `<script>` payload in `TestEchoEscapesSubmittedValue` and `TestHeadersPageEscapesValues`.
- Error state (empty/oversized POST): renders the exact locked error copy, always returns 200 rather than a bare 400 (a deliberate, documented choice — "a browser showing a bare 400 body is a worse demo than a page that explains what went wrong"), boundary-tested at exactly 4096/4097 bytes (`TestEchoAtSizeBoundary`).
- Headers-page empty backstop (`TestHeadersPageEmptyBackstop`) and status-page `—` fallback for unparseable `RemoteAddr` (`TestStatusPagePartialFallback`, explicitly asserts no panic) are both implemented, not just assumed.
- Loading state deliberately relies on the browser's native full-page-reload indicator — correctly matches the "zero JavaScript" delivery constraint rather than building an unnecessary spinner.
- `renderPage` fails closed to a clean 500 on any template execution error rather than a half-written page.
- No destructive actions exist in this phase, so the "confirmation for destructive actions" criterion is correctly not applicable.
- No issues found. This pillar is a clean pass.

---

## Registry Safety

Not applicable — no `components.json`/shadcn initialization exists in this pure-Go project (confirmed by UI-SPEC's own Design System table: "shadcn init gate is not applicable to this stack"). Registry audit skipped per the audit's own gating rule.

---

## Files Audited

- `.planning/phases/03-in-process-termination/03-UI-SPEC.md` (design contract)
- `examples/tunnelweb/site/site.go`
- `examples/tunnelweb/site/pages.go`
- `examples/tunnelweb/site/style.css`
- `examples/tunnelweb/site/site_test.go`
