Tollgate is a gateway every AI agent request and answer passes through. It reads like a security document: white paper, black ink, one red, and redaction bars, because hiding what must not leak is what the product does. The only colour that is not a signal is the canary, the mascot that sits on the gate and reacts to every decision. Use this system for the dashboard, the stage screen, the slides and the video, so all four look like one product.

## Themes

- **Light** (`data-theme="light"`, the default): the console, slides and the stage screen. Black on white projects well in a bright hall.
- **Dark** (`data-theme="dark"`): the video and a night mode for the console. It inverts paper and ink; the canary and the red stay.
- One theme per surface. Never place a dark panel inside a light page.

## Content fundamentals

- Write like an audit report: plain, specific, short. "Blocked: decode.rescan", not "Threat neutralised!".
- Decisions are the API words: `allow`, `redact`, `block`, `kill_session` (badges may write "kill").
- Machine text is always `data` (IBM Plex Mono): rule ids `pii.iban`, `decode.rescan`, `sig.shadowray-cve-2023-48022`, hashes `p-2b3a0e6545fd`, file names `policy.yaml`.
- Headlines on slides and the stage screen are uppercase, condensed `display` / `display-xl`. Everything else is sentence case.
- Numbers carry units and come from real measurements ("tier 0 p50 0.48 ms", "bypass rate 15.7 %"). Label any example as an example.
- No emoji, no exclamation marks.

## Visual foundations

### Colour

- `paper` and `ink` do almost all the work. `paper-2` for raised areas.
- `signal` red is the only accent. It means "stopped" (block, kill, failures) or marks the single number a slide is about. Never decorative.
- Decisions: `allow` is plain ink (passing is normal); `redact` is a black `redact-bar`; `block` is signal text; `kill` is a signal fill with `on-signal` text. Always write the word too.
- `canary`, `canary-shade`, `canary-beak` belong to the mascot only. No yellow buttons, warnings or highlights.

### Redaction bars (the brand device)

- A solid `redact-bar` rectangle, square corners, height about 60 % of the cap height of the text it sits in, covering whole words.
- Use it in the wordmark (TOLL▬GATE), over the redacted part of an example ("Pay invoice to ████████"), and at most once per headline as a gag ("MODELS ████ WHEN UNSURE").
- In motion, a bar grows from left to right over the words in 220 ms (ease-out). That is the redact animation everywhere.

### Type

- Archivo (variable width and weight) for everything that is not machine text: condensed (font-stretch 72 %) and uppercase for `display-xl` and `display`, 80 % for `metric`, normal width for text. IBM Plex Mono for `data`, `data-lg` and `caption`.
- Font files are in `fonts/` (SIL OFL). Load them; do not fall back to Inter or Roboto.
- Console: `body-dense` 13 px, `heading` uppercase 15 px for panels, `title` for pages, `metric` for tiles. Stage and slides: nothing a hall must read under 24 px; rule ids in `data-lg`.
- Tabular figures wherever numbers line up.

### Rules, space, shape

- Structure is made with `rule`: 2 px under a page or slide header and over its footer, 1 px between table rows. No cards with shadows; no rounded panels.
- Square corners everywhere (`radius-0`). `radius-sm` only on inputs and buttons. `radius-mascot` only on the canary. The softness of the bird against the square system is deliberate.
- 12-column grid; slides and stage screen keep `space-12` margins at 1280 px (`space-16` at 1920 px).

### Motion

- The canary acts out every decision. Idle: still, blinks every few seconds. Allow: the arm lifts (rotate −55° about the post, 420 ms, slight overshoot) and the bird hops. Redact: a bar slides over its eyes. Block: the arm shakes (300 ms) and the bird frowns and puffs up. Kill: the bird tips off the post (550 ms, ease-in).
- Text redaction: bars grow over words left to right. Numbers count up only once, on entry.
- Respect `prefers-reduced-motion`: switch states instantly, no shake.

## The canary

- Built from five shapes: body (rounded rect, `radius-mascot`), wing, tail, beak, eye; it sits on the gate (post plus striped arm in `ink`).
- `assets/Logos/canary-light.svg` / `canary-dark.svg` is the full mark; `favicon.svg` is the bird alone on an ink tile for 16–64 px.
- States are classes on the mascot root: `is-idle`, `is-allow`, `is-redact`, `is-block`, `is-kill` (see the Canary component).
- Do not redraw it, add a mouth, change its colours or show it without the gate except in the favicon.

## Logo

- `lockup-light.svg` / `lockup-dark.svg`: canary mark plus TOLL▬GATE wordmark. `wordmark-*.svg` where the mark is already on screen.
- Clear space: the height of the bar in the wordmark on every side. Minimum wordmark width 96 px.

## Surfaces

- **Console (Light):** dense tables with 1 px rules, decision badges in every row, the policy hash in the header, the canary small in the top bar mirroring the latest decision.
- **Stage `/live` (Light):** one screen readable from the back of a hall: the canary large, reacting live; the newest four decisions as rows; posture score and blocked count as `metric`.
- **Slides (Light, 16:9):** header rule with the wordmark and section number; one uppercase headline; at most three facts; a footer rule with up to three metrics.
- **Video (Dark or Light):** the canary is the main character; text appears and gets redacted with bars; red only on blocks.
