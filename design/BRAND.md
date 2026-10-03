Tollgate looks like a calm operations console: light grey ground, white panels, thin borders, system type, and colour only where a decision was made. The one character in it is the canary, a small yellow bird on a toll gate that reacts to every decision. These rules come from the shipped dashboard (`apps/dashboard/app/globals.css`); slides, the video and any new screen follow the same language.

## Principles

- Quiet by default. Neutral surfaces, one interface accent (`accent`), and decision colours used only for decisions.
- Information first. Summary numbers before detail, real values with units, nothing decorative that a reader has to decode.
- One personality element: the canary. Everything else stays plain so the bird and the decisions stand out.

## Content

- Plain, specific sentence case: "Last edit rejected, previous version still active", not "Oops!".
- Decisions are the API words: `allow`, `redact`, `block`, `kill session` (in badges), "would block" in monitor mode.
- Rule ids, hashes, keys and timestamps in `data` (mono): `pii.iban`, `decode.rescan`, `p-2b3a0e6545fd`.
- Numbers carry units and come from real measurements ("tier 0 p50 0.48 ms", "bypass rate 15.7 %"); examples are labelled.
- No emoji, no exclamation marks.

## Colour

- `bg` behind everything, `panel` for panels and cards, `line` for borders, `ink` for text, `mute` for secondary text.
- `accent` for links, primary buttons and the focus ring (2 px `accent` outline, 1 px offset; inputs get an `accent-soft` halo).
- Decision badges: `allow` / `allow-bg` / `allow-border`, and the same triple for `redact`, `block`, `kill`. Always the word plus the colour. Monitor mode: dashed border, transparent fill, "would block".
- `canary`, `canary-shade`, `canary-beak` belong to the mascot only.

## Type

- System fonts, no downloads: `sans` for text, `mono` for machine text. Tabular figures for numbers.
- Console: `body` 13 px, `page-title` 16 px semibold, `panel-title` 12 px semibold, `tile-value` 22 px semibold, `label` 11 px in `mute`, `badge` 11 px medium.
- Slides: `slide-display` / `slide-title` semibold with tight tracking; split a headline into a statement in `ink` and its continuation in `mute` ("Rules first." / "Models only when unsure."). `slide-lead` 20 px in `mute`. `slide-metric` in white metric cards. `data-slide` for rule ids.

## Shape and space

- Panels: `panel` fill, 1 px `line` border, `radius-panel` (6 px), header row with `panel-title` and a bottom `line`. No shadows except a small one on hover popovers.
- Badges `radius-badge` (3 px); buttons and inputs `radius-control` (4 px), 28 px tall; slide cards `radius-card` (10 px).
- Console spacing: `space-3` inside panels, `space-2` between tiles, `space-4` between panels. Slides: `space-11` top and bottom, `space-14` sides, `space-10` between metric cards.

## The canary

- A rounded yellow body, a folded wing, a tail, a beak and one eye, sitting on a gate post with a striped arm. Inline the SVG from the Canary component; states are classes on its root: `is-idle`, `is-allow` (arm lifts, bird hops, happy eye), `is-redact` (a black bar over its eyes), `is-block` (arm shakes, bird puffs up and frowns), `is-kill` (bird tips off the post, eyes become crosses).
- Console: the head only (`canary-head.svg`, 20–24 px) next to the wordmark, mirroring the latest decision if animated. Slides: the full mark at 300–420 px on the title slide. Video: the main character.
- Respect `prefers-reduced-motion`: change state instantly. Do not add a mouth, change its colours, or put it anywhere it does not react to Tollgate.

## Logo

- `logo.svg`: canary head plus "tollgate" in lowercase semibold, on `bg` or `panel`. `logo-on-dark.svg` on `ink` grounds. `favicon.svg` for the browser tab.
- Keep clear space of the head's width on each side; minimum height 18 px.

## Slides

- 16:9 on `bg`: logo top left, section and slide number top right in `mute`, a two-tone headline, one supporting card (decisions, a diagram or a screenshot on a `panel` card with `radius-card`), up to three metric cards at the bottom.
- Screenshots of the console are shown as they are, inside a `panel` card.
