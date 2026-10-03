# Checkpoints

## Checkpoint 1 — plan + schemas (Sat 3 Oct, ~17:00 CEST)

### State
- M0 done, tagged `m0`: workspaces, tsconfig strict, `bun run check` exit 0, `/healthz` ok.
- Ollama 0.6.2 (above the Probllama fix). `llama3.2:3b` and `llama-guard3:1b` both pulled (17:00 CEST). Build stays mock-first anyway.
- SPEC.md marked "reference only": HANDOFF.md > PLAN.md > SPEC.md. Names and routes come from PLAN.md section 1 and `packages/policy`.

### Schemas (draft, uncommitted until approved)
- `packages/policy/src/schema/common.ts` — Action, Decision, Mode, Tier (0 | 1 | 2 | "output"), OWASP ids, rule-id format.
- `packages/policy/src/schema/policy.ts` — `PolicySchema` (strict everywhere; misspelt keys rejected).
- `packages/policy/src/schema/decision.ts` — `DecisionRecord`, `Hit`, `Stages`, `Reason`.
- `packages/policy/src/schema/feed.ts` — `FeedEntry`, `Feed` (regexes compiled at validation time).
- `packages/policy/src/schema/testcase.ts` — `TestCase`, `Seed`.
- `packages/policy/src/schema/contract.ts` — SSE events, `/metrics`, `/admin/policy|stats|agents|feed|redteam`, `/audit/verify`.
- `packages/policy/src/owasp.ts` — `RULE_OWASP`, `owaspFor()`, `NOT_COVERED`.

### Decisions not in HANDOFF
1. `policy.yaml` has two control sections: `controls.*` (request path) and `output.*` (response path). Rule ids: `pii.iban` vs `output.pii`.
2. Clean pass: `rule_id: "none"`, `tier: "output"`. Auth, budgets, model allowlist are tier 0.
3. "Uncertain" = tier-1 score in `semantic.uncertain_band` (two classifiers disagreeing average to 0.5) OR tier 1 safe + any tier-0 soft signal.
4. Approval-listed tool calls (`send_email`) are blocked with `tool.approval`. No approval queue UI.
5. `ADMIN_TOKEN` optional; unset = `/admin/*` open on localhost. Gateway never refuses to start for it.
6. `policy_version` = first 12 hex of sha256 of the raw file bytes (as CLAUDE.md says).
7. Echo upstream is driven by header `X-Tollgate-Echo` (presets `pii | secret | canary | exfil | sysprompt | tool:<name>`, or base64 JSON), honoured only when `UPSTREAM=echo`.
8. Monitor mode: `enforced: false`, `reason: "would_act"`. Budgets are only recorded in monitor unless `budgets.enforce_in_monitor: true`.
9. Feed `pattern` is always one string (regex, URL regex, pickle-global regex, or `"ollama < 0.1.34"`), so judges can edit it.
10. Kill switch is per agent (`agent.locked`, unlock via `POST /admin/agents/<id>/unlock`), not per session.

### Time plan (CEST)
| Slot | Work |
|---|---|
| 17:00–17:30 | Checkpoint 1 approval, freeze commit (`packages/policy` + loader + hot reload + validator + tests), spawn B, C, D |
| 17:30–19:30 | M1 proxy, identity, hot reload, SSE, echo upstream, provider interface |
| 19:30–22:30 | M2 tier-0 controls + budgets |
| 22:30–00:30 | M4 feed + audit + telemetry + demo (model-free, moved before M3) |
| 00:30–02:30 | M3 semantic tiers (mock first, Ollama adapter last) + output scan + stream redaction |
| 02:30 | Checkpoint 2 |
| 02:30–04:00 | M6 runner part 1, or M7-lite if Checkpoint 2 is before 02:15 |
| 04:00–07:00 | Sleep |
| 07:00–09:30 | M6 part 2, M5 integration, M8 |
| 09:30–10:00 | M9 numbers, screenshots, PDF, fresh clone |
| 10:00 | Code freeze, submit by 10:30 |

### Subagents after the freeze (Sonnet, medium)
- B dashboard: `apps/dashboard/**` only, builds against `contract.ts` with a mock SSE until M4.
- C fixtures: `tests/cases/*.yaml` only, ≥ 1 positive + 1 negative per rule id in `RULE_OWASP`.
- D seeds: `tests/redteam/seeds/*.yaml` only, ~40 seeds, attributed.
