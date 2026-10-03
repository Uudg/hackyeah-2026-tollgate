# tests/

One command runs everything: `bun test`. Model-free subset: `bun run test:fast`.

- `cases/*.yaml` — fixture cases (format: docs/SPEC.md §11.1), run by `tests/runner.test.ts` against `policy.test.yaml`.
  Cases tagged `model` need Ollama and skip cleanly with the SPEC message when it is absent.
- `cases/generated/` — written by the Red Team Loop; every file is a bypass turned into a regression test.
- `policy.test.yaml` — the policy the suite boots on (semantic disabled by default). Never test against `../policy.yaml`.
- `redteam/seeds/*.yaml` — attack seeds for the Red Team Loop (SPEC §12.1). Mutation operators live in
  `apps/gateway/src/redteam/mutators.ts` (SPEC §12.2); there is no separate mutator file to maintain.
- Seeds were written by hand following public families in garak (Apache-2.0) and promptfoo (MIT); all secrets
  and personal data in them are documentation examples or invented.
