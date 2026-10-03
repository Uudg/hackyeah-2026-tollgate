// PII detection (SPEC §7.1): rule ids pii.<entity>, OWASP LLM02. Detectors run in a fixed order and a later
// detector never claims a span an earlier one already took (a card number is not also a phone number).
import type { PiiEntity } from "@tollgate/policy";
import { makeHit, overlaps, type Action, type Hit } from "../types.ts";
import { IBAN_RE, ibanMatchLength } from "./iban.ts";
import { CARD_RE, cardValid } from "./card.ts";
import { PESEL_RE, peselValid } from "./pesel.ts";
import { EMAIL_RE } from "./email.ts";
import { PHONE_RE, phoneValid, IP_RE, ipValid } from "./phone.ts";

export { ibanValid } from "./iban.ts";
export { luhnValid } from "./card.ts";
export { peselValid } from "./pesel.ts";

interface Detector { entity: PiiEntity; re: RegExp; accept: (m: string) => number }
const all = (ok: (m: string) => boolean) => (m: string) => (ok(m) ? m.length : 0);

const DETECTORS: Detector[] = [
  { entity: "iban", re: IBAN_RE, accept: ibanMatchLength },
  { entity: "card", re: CARD_RE, accept: all(cardValid) },
  { entity: "pesel", re: PESEL_RE, accept: all(peselValid) },
  { entity: "email", re: EMAIL_RE, accept: all(() => true) },
  { entity: "phone", re: PHONE_RE, accept: all(phoneValid) },
  { entity: "ip", re: IP_RE, accept: all(ipValid) },
];

export interface PiiOptions { entities: readonly PiiEntity[]; action: Action; field: string; owasp?: string[] }

export function scanPii(text: string, o: PiiOptions): Hit[] {
  const hits: Hit[] = [];
  const taken: Array<[number, number]> = [];
  for (const det of DETECTORS) {
    if (!o.entities.includes(det.entity)) continue;
    for (const m of text.matchAll(det.re)) {
      const len = det.accept(m[0]);
      if (len === 0) continue;
      const start = m.index!, end = start + len;
      if (overlaps(taken, start, end)) continue;
      taken.push([start, end]);
      hits.push(makeHit({
        controlId: "pii", ruleId: `pii.${det.entity}`, action: o.action, owasp: o.owasp ?? ["LLM02"],
        field: o.field, text, start, end, label: det.entity, details: { entity: det.entity },
      }));
    }
  }
  return hits;
}
