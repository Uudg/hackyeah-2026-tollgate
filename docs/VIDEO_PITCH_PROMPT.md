# Tollgate pitch video — Claude Code prompt

Run after the submission video exists (`docs/VIDEO_SUBMISSION_PROMPT.md`), in the same folder and terminal setup:

    cd ~/Documents/tollgate-promo && claude

Model: Opus 5.5 high (Sonnet 5.5 high if quota is short). Start in Plan mode. Paste everything below the line.

---

Make a short pitch video for Tollgate from the submission video project in this folder: 20–25 seconds, 1920x1080, silent-safe. It may open my stage pitch in a big hall, so it must read from the back of the room in one glance per beat, and it must not explain the details (the submission video does that).

## Reuse, do not rebuild
- Use the existing `captures/*.json`, `src/data.js` and the parts in `src/parts/` from the submission video. If `captures/` is missing or older than the repo's current commit, rerun `bun run capture` first (same isolation rules as the submission prompt: copies in `runtime/`, never write to `~/Documents/hackyeah2026`).
- Same design system: `~/Documents/hackyeah2026/design/` (read `design/README.md` and `design/BRAND.md`); the canary from `design/mascot/canary.svg` is the main character.
- New composition in `src/pitch/`; output `out/tollgate-pitch.mp4` and a 1080x1080 crop `out/tollgate-pitch-square.mp4` if the layout allows.

## Storyboard (about 24 s)
1. **0–3 s.** `bg` ground, the canary on its gate, still. One line: "AI agents now hold keys, tools and data."
2. **3–15 s.** Four real decisions, about 3 s each, big: a request card slides in (real prompt, shortened), the decision badge lands large with the rule id, and the canary acts it out: allow (arm lifts), redact (bar over its eyes, the IBAN digits replaced), block (arm shakes), kill (canary tips over, "session killed").
3. **15–20 s.** "One policy file." The real one-line `policy.yaml` change and the before/after decision side by side; then one big real number (tier-0 overhead p50 or the test count).
4. **20–24 s.** The canary back on the post, the arm lifts, logo and tagline: "One policy file between your agents and everything they can touch." Hold the last 15 frames still so I can start talking.

## Rules
- Text at least 48 px; at most one line of copy per beat; nothing a hall cannot read.
- Everything on screen comes from `captures/`; no invented numbers.
- Calm motion as in the submission video; shake only on block. No audio required; if you add the same light ticks, keep a silent version too.

## How to work
Plan mode first: the timeline and which captures each beat uses; wait for my OK. Then build, snapshot one frame per beat, check them, render, extract 6 frames and check them. Deliver `out/tollgate-pitch.mp4` (and the square one) and add `bun run render:pitch` to the README.
