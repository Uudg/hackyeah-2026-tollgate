# design/ — Tollgate design system (v3)

Built from the shipped dashboard: same colours, badges, panels and system fonts as `apps/dashboard/app/globals.css`, plus one personality element, the canary. Use it for slides, the video and any new screen. The dashboard itself already matches; it only needs the logo, favicon and (optionally) the canary.

- `BRAND.md` — the rules. Read first.
- `tokens.css` / `tokens.json` — colours, type styles, spacing, radii. Values equal the dashboard's `globals.css`.
- `components.css` — decision badges, panels, tiles, tables, slide layout, metric cards, and the canary's animation states.
- `mascot/canary.svg` — the canary as inline SVG with state hooks (`is-idle | is-allow | is-redact | is-block | is-kill` on the root). See `mascot/README.md`.
- `logo/` — `logo.svg` (head + "tollgate"), `logo-on-dark.svg`, `canary.svg` (bird on gate), `canary-head.svg` (console header), `favicon.svg`.
- `examples/` — open `SlideTitle.html`, `Slide.html` and `Canary.html` in a browser.
- `_archive-v1/`, `_archive-v2/` — rejected directions. Do not use.
