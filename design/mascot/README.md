# Canary

The mascot: a canary on the toll gate that acts out the latest decision.

- Inline the SVG from this preview (root `<svg class="tg-canary is-idle">`); an `<img>` cannot animate.
- The consumer sets one class from the latest decision: `is-allow`, `is-redact`, `is-block`, `is-kill` (kill_session), then back to `is-idle` after about 1.5 s. Coming back from `is-kill`, add `no-anim` for one frame so the bird reappears on the post.
- Sizes: 300–420 px on a title slide or stage panel; in the console use `canary-head.svg` at 20–24 px instead.
