# design/ — Tollgate design system

The one source for how Tollgate looks: dashboard, stage screen `/live`, slides and the product video.

- `BRAND.md` — the rules. Read it first.
- `tokens.css` — CSS custom properties for both themes (`data-theme="night"` default, `data-theme="day"` for the console) plus `@font-face` and type classes (`.display-xl`, `.body-dense`, `.data`, …). Generated from `tokens.json`; edit `tokens.json`, then regenerate.
- `tokens.json` — the same tokens as data (for Remotion, slides, scripts).
- `components.css` — decision badge, rule chip, stage strip, metric tile, budget bar, barrier stripe.
- `fonts/` — Overpass and Overpass Mono variable woff2 (SIL OFL 1.1). Load these; no web font downloads at runtime.
- `logo/` — lockups and marks for Night and Day, and `favicon.svg`.
- `examples/` — static HTML references: open `examples/Slide.html` and `examples/StageScreen.html` in a browser. Values in examples are illustrative.

Mapping from the current dashboard tokens (apps/dashboard/app/globals.css): `--bg`→`--ground`, `--panel`→`--surface`, `--ink`→`--ink`, `--mute`/`--faint`→`--ink-muted`, `--line`→`--line`, `--line-strong`→`--line-strong`, `--accent`→`--brand`, `--allow/-bg`→`--allow/--allow-soft`, `--redact/-bg`→`--redact/--redact-soft`, `--block/-bg`→`--block/--block-soft`, `--kill/-bg`→`--kill/--kill-soft`.
