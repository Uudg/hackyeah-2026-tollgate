# Tollgate

AI Control Layer: an OpenAI-compatible proxy that enforces one `policy.yaml` on every agent ↔ model / tool interaction.

## Setup

```sh
bun install
ollama pull llama3.2:3b && ollama pull llama-guard3:1b   # optional: everything except model-backed tests runs without them
bun run dev                                              # gateway :8787, dashboard :3000
```

Run the tests: `bun test`. Plan: [docs/PLAN.md](docs/PLAN.md).
