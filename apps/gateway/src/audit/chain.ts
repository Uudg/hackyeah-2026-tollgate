// Audit line format and hashing (SPEC §9): hash = sha256(prev_hash + "\n" + canonicalJson(record)).
import { canonicalJson, sha256 } from "@tollgate/policy/loader";

export const GENESIS = "0".repeat(64);

export interface AuditLine { seq: number; prev_hash: string; hash: string; record: Record<string, unknown> }

export const lineHash = (prevHash: string, record: unknown) => sha256(`${prevHash}\n${canonicalJson(record)}`);
