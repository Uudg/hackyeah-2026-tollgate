# StageStrip

Shows the path of one request through the pipeline, which stage decided, and how long each stage took.

- Stages in this order: auth, budget, tier 0, tier 1, tier 2, output. The consumer provides each stage's time from the decision record's per-stage latency.
- Mark the deciding stage with `tg-step--decided` plus `is-block`, `is-redact` or `is-kill` (allow keeps the brand underline). Mark stages that did not run with `tg-step--skipped` and say why in the note ("not reached", "not uncertain").
- This is the product's main idea made visible: cheap checks first, models only when needed. Use it on the event detail page, the playground and the stage screen.
