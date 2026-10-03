Tollgate is a gateway every AI agent request and answer passes through. The brand is a road toll gate: a post, a cyan barrier arm that lifts for clean traffic and drops on blocked traffic, and a small canary perched on the arm that falls when a secret leaks. Use this system for the dashboard, the stage screen, the slide deck and the product video, so all four look like one product.

## Themes and where each is used

- **Night** (`data-theme="night"`, the first theme) is the identity: stage screen `/live`, slides, video, social images. Ground `ground` #070a12, text `ink`.
- **Day** (`data-theme="day"`) is the working console: the dense dashboard pages a security analyst reads for hours. Ground `ground` #f3f5f8, panels `surface`.
- Never mix themes inside one surface. A slide is Night end to end; a console page is Day end to end, and offers the Night toggle.

## Content fundamentals

- Write plainly and specifically. Name the thing the reader sees: "Blocked", "Redacted", "Policy v12 loaded", never "Operation completed".
- Decisions are the API words in lowercase: `allow`, `redact`, `block`, `kill_session` (badges may shorten the last to "kill").
- Rule ids, hashes, keys and file names are always in `data` (mono): `pii.iban`, `decode.rescan`, `sig.shadowray-cve-2023-48022`, `p-2b3a0e6545fd`, `policy.yaml`.
- Numbers carry units and come from real measurements: "tier 0 p50 0.48 ms", "bypass rate 15.7 %". Never invent a figure for a slide or the video; label examples as examples.
- Sentence case for headings and buttons. No exclamation marks, no emoji.
- English for product copy. Short sentences: one idea each. On stage and slides, at most 12 words per line of copy.

## Visual foundations

### Color

- `brand` (cyan) is the gate and the one accent: the barrier arm, links, primary buttons, focus ring. Allowed traffic uses the same hue (`allow` aliases `brand`): passing the gate is the product working.
- Decision colors are semantic and only ever mean a decision: `allow`, `redact`, `block`, `kill`, each with a `-soft` tint for badge and row backgrounds. Always pair the color with the word; never color alone.
- `canary` is reserved for the canary. Use it for the mascot and for canary-trip moments (a canary tripped toast, the kill frame in the video). Never for ordinary warnings: those are `redact`.
- Text on `brand` uses `on-brand`; text on `canary` uses `on-canary`.
- Neutrals carry a slight blue bias toward the brand. Do not substitute pure greys.

### Type

- One family, Overpass, inspired by the highway signage type the toll-road idea comes from, plus Overpass Mono for machine text. Font files are in `fonts/`; load them, do not fall back to Inter or Roboto.
- Console: `body-dense` (13 px) for text and tables, `heading` for panel titles, `title` for page titles, `metric` for big numbers, `label` (uppercase in CSS) for tile labels.
- Stage and slides: `display-xl` for the one hero line, `display` for slide titles, `body` (15 px) only for footnotes. Anything a hall must read is 24 px or larger.
- Use tabular figures (`font-variant-numeric: tabular-nums`) wherever numbers line up.

### Space, shape, borders

- Spacing steps `space-1` to `space-16` (4 px base). Console panels pad `space-3`; stage cards pad `space-8`; slides keep `space-16` margins at 1920 × 1080.
- Radii: `radius-sm` badges, `radius-md` controls and panels, `radius-lg` stage cards and slide frames, `radius-pill` dots and toggles only. Do not round everything the same.
- Borders, not shadows: separate panels with a 1 px `line`; controls get `line-strong`. No drop shadows in the console; on stage a soft `brand` glow is allowed on the arm only.
- The barrier stripe (diagonal cuts at `space-12` pitch, as in the mark) is the brand pattern. Use it once per surface at most: the stage header, a slide divider, the video's gate.

### Motion

- The gate arm lifts on allow (rotate up, 160 ms, ease-out) and drops on block (90 ms, ease-in, one 4 px shake that decays). Redact is a scramble of the redacted span into █ characters over 240 ms. Kill: the canary tips off the arm, 400 ms.
- Nothing else moves without a reason. Respect `prefers-reduced-motion`: replace movement with an instant state change and a color flash.

### States

- Focus: 2 px solid `focus` ring, 2 px offset, on every interactive element.
- Monitor mode (would block, traffic passes): the decision badge is outlined instead of filled and says "would block".
- Live connection: a `radius-pill` dot, `brand` when live, `ink-muted` when reconnecting, with the word next to it.

## Iconography

- No icon library. Use words first: a badge says "block", a button says "Export JSONL".
- Where a glyph helps (stage strip arrows, status dots), draw simple 1.5 px line shapes in `ink-muted` or the relevant decision color.
- The logo is the only illustration. The canary appears only in the mark and in canary moments.

## Logo

- `assets/Logos/tollgate-lockup-night.svg` on Night grounds, `tollgate-lockup-day.svg` on Day grounds; the marks alone for small spaces; `favicon.svg` for the browser tab.
- Keep clear space of one post width (9/64 of the mark) on every side. Minimum mark size 20 px; under that use the favicon.
- Do not recolor, rotate, add effects, or separate the canary from the arm.

## Surfaces

- **Console (Day):** dense, scannable, summary before detail. Decision badges in every event row; policy hash badge in the header.
- **Stage `/live` (Night):** one screen, readable from the back of a hall. Posture score in `display-xl`, live decisions flowing through a tier strip (tier 0 → tier 1 → tier 2 → output), budget ring, last rule id in `data` at 24 px+.
- **Slides (Night, 16:9):** one idea per slide, a `display` title, at most three short lines, one visual. Real screenshots of the console go on a `surface` frame with `radius-lg`.
- **Video (Night):** same palette and type; decisions shown with the motion rules above.
