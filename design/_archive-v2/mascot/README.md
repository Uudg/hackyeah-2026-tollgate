# Canary

The mascot: a canary on the toll gate that acts out the latest decision.

- Markup: the inline SVG from this preview, root `<svg class="tg-canary is-idle">`. Inline it; an `<img>` cannot animate or take theme colours.
- The consumer sets one state class from the latest decision record: `is-allow`, `is-redact`, `is-block`, `is-kill` (`kill_session`), back to `is-idle` after about 1.5 s. Coming back from `is-kill`, add `no-anim` for one frame so the bird reappears on the post instead of flying back.
- Sizes: 240 px or more on the stage screen, 28–40 px in the console top bar (no animation below 28 px; use `favicon.svg` under 24 px).
- Do not add states, a mouth, or other colours.
