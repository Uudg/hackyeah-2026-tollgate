# DecisionBadge

Shows the gateway's decision for one request or response: allow, redact, block or kill.

- Markup: `<span class="tg-badge tg-badge--block">block</span>`; add `tg-badge--monitor` when the policy is in monitor mode and the action was only recorded (write "would block"); `tg-badge--lg` on the stage screen.
- The consumer provides the decision word. Always render the word; the color never stands alone.
- Pair it with a rule chip `<span class="tg-rule">decode.rescan</span>` in tables and event rows.
- Do not use decision colors for anything that is not a decision.
