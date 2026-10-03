# Tollgate promo video — Claude Code prompt

Run this in a SEPARATE terminal and a SEPARATE folder from the main build, so it never touches the repo or git history of the gateway:

    mkdir -p ~/Documents/tollgate-promo && cd ~/Documents/tollgate-promo && claude

Model: Opus 5.5, effort high (Sonnet high if the main build is hitting rate limits). Start in Plan mode (Shift+Tab). Paste everything below the line.

---

Make a dynamic 15-second motion graphics video that shows what an incredible motion designer I am, like it's my showreel for a résumé — and that doubles as the preview video for my hackathon project, Tollgate. Go all out.

## The project (so the video is truthful)
Tollgate is an AI Control Layer: an OpenAI-compatible gateway that every AI agent request and response passes through. One policy.yaml controls everything. Cheap deterministic checks run first (auth, model allowlist, PII and secret detection, Unicode and encoding tricks, a feed of historical-attack signatures); a small local model is consulted only for ambiguous cases. It enforces token and cost budgets, redacts or blocks, logs every decision in a tamper-evident hash chain, and plants "canary" fake secrets: if one ever appears in output, the session is killed. Hackathon: HackYeah 2026, Goldman Sachs "AI Control Layer" track. Tagline: "One policy file between your agents and everything they can touch."

## Who I am (the showreel part)
Full-stack developer with a 3D-web and motion background: React Three Fiber, GLSL shaders, postprocessing, GSAP-style scroll and timeline animation. The video should demonstrate that range: 3D camera work, custom shaders, kinetic typography, easing and timing discipline, beat-synced editing. It must look like a designed piece, not a screen recording or a slideshow.

## Technical setup
- Folder: ~/Documents/tollgate-promo (already open). Remotion (React) with @remotion/three (react-three-fiber) and @react-three/postprocessing for bloom, chromatic aberration, grain, vignette. Write custom GLSL for at least one effect (packet glow or the gate scan).
- 1920x1080, 30 fps, exactly 450 frames (15.0 s), H.264 mp4 to out/tollgate-promo.mp4. Also render a poster still (out/poster.png) and a 1080x1080 centre-crop variant (out/tollgate-promo-square.mp4) if the layout allows.
- My internet is very slow. Install only what is needed, no web fonts, no stock assets, no downloads at render time. If Remotion tries to download its own Chromium, point it at the Chrome already on this Mac with --browser-executable instead. Use system fonts (SF Mono / Menlo for code, SF Pro / Helvetica Neue for display).
- Do not depend on the Tollgate gateway or the other repo being up. Everything is scripted in the composition. Put every number and label in one src/data.ts so it can be updated at the end; use only the placeholders listed there, never invented stats.
- Do not modify anything outside ~/Documents/tollgate-promo.

## Look
Near-black blue background (#05070d), cyan (#4de2ff) = allowed, amber (#ffb347) = redacted, red (#ff4d5e) = blocked, warm yellow (#ffd84a) only for the canary. Thin line work, glass panels, soft bloom, very subtle film grain. Mono type for machine text, one big geometric sans for titles. Generous negative space; one hero element per beat. Think a product launch video, not a hacker movie: no green matrix rain, no padlock clip art, no stock shield icons.

## Storyboard (30 fps, cut on a 120 BPM grid: a hit every 15 frames)
- 0.0–1.2 s, cold open. Black. A single cyan line draws down the centre; mono text types "POST /v1/chat/completions". A tick sound on the beat (see Audio).
- 1.2–4.0 s, the flood. Camera dollies in on a 3D scene: dozens of small rounded-rectangle "packets" stream along lanes in perspective toward the Gate (two slim pillars with a barrier arm and a thin ring around them that is the budget meter). Each packet carries a tiny mono label (chat, tool_call, mcp). Build tempo and parallax.
- 4.0–7.0 s, verdicts, one every beat, with a rule chip popping next to each: (1) a clean packet, the arm lifts, it passes in cyan; (2) a packet whose text reads "card 4111 1111 1111 1111" has its digits scramble into ████ in amber and continues (chip: pii.card); (3) "ignore all previous instructions" shatters into red shards with a small camera shake (chip: prompt_injection); (4) a base64 blob unwraps into readable text mid-air, then shatters (chip: decode.rescan); (5) a packet matching a known exploit, flash and block (chip: sig.shadowray-cve-2023-48022).
- 7.0–9.0 s, the eye. One ambiguous packet slows to bullet-time. A scanning ring (the custom shader) sweeps it, a small "tier 1 → tier 2" label ticks over, then the verdict lands. Make the time-dilation read clearly: everything else crawls.
- 9.0–10.5 s, the toll. The budget ring around the gate drains to red. The arm slams down; packets pile up and ricochet. Chip: budget.tokens_per_hour · 429.
- 10.5–12.0 s, the canary. A small yellow canary (built from simple primitives, charming, 6 to 8 shapes max) is perched on the barrier arm all along, tiny in earlier shots. A response packet leaks a fake key (AKIA… in mono); the canary tips over with a feather puff, a red pulse spreads, chip: canaries.in_output · session killed.
- 12.0–13.5 s, one file. Split screen: policy.yaml typed live, "action: block" is replaced by "action: redact"; the gate geometry morphs to match on the same beat; toast "policy.loaded". Along the bottom, audit-log blocks snap onto a hash chain, one per recent decision.
- 13.5–15.0 s, resolve. Camera pulls back through a glass dashboard panel (a posture score counts up, a small blocked-over-time line draws itself), then wipes to the title: TOLLGATE, with the barrier arm lifting over the wordmark, the canary landing on top, tagline fading in under it. Hold the last 12 frames still.

## Craft requirements
- Easing everywhere, no linear moves. Use springs with overshoot on pops, expo-out on camera, and consistent durations.
- Motion blur on fast moves (sub-frame accumulation or a velocity-based blur pass).
- Camera shake only on blocks, short and decaying. Never shake on allowed packets.
- Every beat should read in a single glance at 1080p and on a phone-sized preview. Text minimum 28 px at 1080p.
- No element appears without an entrance and a reason.
- Keep everything resolution-independent so the square crop works.

## Audio (optional, do last)
Synthesise it locally: ffmpeg lavfi or a small script producing a 120 BPM kick/tick bed, a riser into the title, and a soft glass hit on each block. No downloaded samples. Mix to -14 LUFS and mux into the mp4. If it is not good, ship the silent version and say so.

## How to work
1. Plan mode first: show me the scene graph, the timeline (frame ranges per beat), the component list, and the dependency list. Wait for my OK.
2. Build the skeleton with placeholder boxes timed to the storyboard, render one still per beat, and look at them yourself before polishing.
3. Polish beat by beat. After each beat, render stills at the key frames (first hit, peak, settle) and review them for overlaps, clipped text and weak contrast before moving on.
4. Render the full video, extract 8 evenly spaced frames, and check them. Report render time.
5. Deliver: out/tollgate-promo.mp4, out/poster.png, and a README with the one command to preview (npx remotion studio) and the one command to render.

Do the whole thing without asking me questions; make the call and tell me what you chose. Stop only at the plan checkpoint.
