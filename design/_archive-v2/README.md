# design/ — Tollgate design system (v2, "Redacted" + the canary)

One source for how Tollgate looks: dashboard, stage screen `/live`, slides and the product video. Live reference page: the "Tollgate" design system artifact.

- `BRAND.md` — the rules. Read first.
- `tokens.css` — CSS custom properties for both themes (`data-theme="light"` default, `data-theme="dark"`), `@font-face`, type classes (`.display-xl`, `.metric`, `.data`, …). Generated from `tokens.json`.
- `tokens.json` — the same tokens as data (Remotion, slides, scripts).
- `components.css` — decision badges, redaction bar (`.tg-redact`), decision table, metrics, headline, rule header, and the canary's animation states.
- `mascot/canary.svg` — the canary as inline SVG with state hooks; inline it and set `is-idle | is-allow | is-redact | is-block | is-kill` on the root. See `mascot/README.md`.
- `logo/` — lockups, wordmarks, static canary marks, favicon.
- `fonts/` — Archivo (variable width + weight) and IBM Plex Mono, SIL OFL. Load these locally.
- `examples/` — static HTML references; open `examples/StageScreen.html` and `examples/Canary.html` in a browser to see the animation.
- `_archive-v1/` — the first, rejected direction. Do not use.

Mapping from the current dashboard tokens (apps/dashboard/app/globals.css): `--bg`→`--paper`, `--panel`→`--paper`, `--ink`→`--ink`, `--mute`/`--faint`→`--ink-muted`, `--line`→`--rule-soft`, `--line-strong`→`--rule`, `--accent`→`--ink`, allow→ink outline badge, redact→black bar badge, block→`--signal` outline, kill→`--signal` fill. Square corners everywhere.
