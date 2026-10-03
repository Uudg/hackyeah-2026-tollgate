// Parse + validate policy and feed files. Errors are returned, never thrown (SPEC §4.2).
import { existsSync, readFileSync } from "node:fs";
import YAML from "yaml";
import type { z } from "zod";
import { PolicySchema, type Policy } from "./schema.ts";
import { FeedSchema, type Feed } from "./feed.ts";
import { feedHash, policyHash } from "./hash.ts";

/** One validation problem, formatted "controls.pii.action: Invalid option ...". */
export interface Issue { path: string; message: string }
export const formatIssue = (i: Issue) => `${i.path}: ${i.message}`;

export function zodIssues(error: z.ZodError): Issue[] {
  return error.issues.map((i) => ({ path: i.path.map(String).join(".") || "(root)", message: i.message }));
}

export type Loaded<T> = { ok: true; value: T; hash: string; loadedAt: string; raw: string };
export type Rejected = { ok: false; errors: Issue[] };
export type LoadResult<T> = Loaded<T> | Rejected;

export interface LoadedPolicy extends Loaded<Policy> { version: number }

export function parsePolicyText(raw: string): LoadResult<Policy> & { version?: number } {
  let data: unknown;
  try { data = YAML.parse(raw); }
  catch (err) { return { ok: false, errors: [{ path: "(yaml)", message: (err as Error).message }] }; }
  const parsed = PolicySchema.safeParse(data);
  if (!parsed.success) return { ok: false, errors: zodIssues(parsed.error) };
  return { ok: true, value: parsed.data, hash: policyHash(parsed.data), loadedAt: new Date().toISOString(), raw, version: parsed.data.version };
}

export function parseFeedText(raw: string): LoadResult<Feed> {
  let data: unknown;
  try { data = JSON.parse(raw); }
  catch (err) { return { ok: false, errors: [{ path: "(json)", message: (err as Error).message }] }; }
  const parsed = FeedSchema.safeParse(data);
  if (!parsed.success) return { ok: false, errors: zodIssues(parsed.error) };
  return { ok: true, value: parsed.data, hash: feedHash(raw), loadedAt: new Date().toISOString(), raw };
}

export function readText(path: string): string | null {
  return existsSync(path) ? readFileSync(path, "utf8") : null;
}

const notFound = (path: string): Rejected => ({ ok: false, errors: [{ path: "(file)", message: `${path} not found` }] });

export function loadPolicy(path: string): LoadResult<Policy> {
  const raw = readText(path);
  return raw === null ? notFound(path) : parsePolicyText(raw);
}

export function loadFeed(path: string): LoadResult<Feed> {
  const raw = readText(path);
  return raw === null ? notFound(path) : parseFeedText(raw);
}
