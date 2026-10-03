// Shadow pricing (pricing.json "demo-paid-model"): the alias is served by llama3.2:3b, recorded under its own name,
// and costs shadow dollars, so spend and USD budgets can be shown without a paid API. llama3.2:3b itself stays free.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chat, getRecord, startGateway, type TestGateway } from "./harness/gateway.ts";

let tg: TestGateway;
beforeAll(() => { tg = startGateway(); });
afterAll(() => tg.stop());

describe("deterministic · shadow-priced demo model", () => {
  test("alias goes upstream as llama3.2:3b, is recorded as demo-paid-model, and costs USD", async () => {
    const r = await chat(tg, "Summarise the Q3 treasury notes in three bullet points.", { agent: "paid-demo", model: "demo-paid-model" });
    expect(r.status).toBe(200);
    expect((r.body as { model: string }).model).toBe("llama3.2:3b"); // the echo upstream answers with the model it was sent
    const rec = await getRecord(tg, r.headers.get("x-tollgate-event"));
    expect(rec.model).toBe("demo-paid-model");
    expect(rec.costUsd).toBeGreaterThan(0);
  });

  test("llama3.2:3b stays at 0 USD", async () => {
    const r = await chat(tg, "Summarise the Q3 treasury notes in three bullet points.");
    const rec = await getRecord(tg, r.headers.get("x-tollgate-event"));
    expect(rec.model).toBe("llama3.2:3b");
    expect(rec.costUsd).toBe(0);
  });
});
