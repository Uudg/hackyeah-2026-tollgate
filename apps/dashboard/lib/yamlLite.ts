// A tiny YAML-subset reader used ONLY by mock mode, so that "Validate" and "Save" in /policy work without a gateway.
// Supports: nested maps, "- item" lists of scalars, [a, b] flow lists, quoted strings, numbers, booleans, null, # comments.
// Not supported (throws): tabs, anchors, multi-line scalars, lists of maps. The live gateway uses the real `yaml` package.

interface Tok { indent: number; text: string; n: number }

function stripComment(s: string): string {
  let q: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (q) { if (c === q && s[i - 1] !== "\\") q = null; continue; }
    if (c === '"' || c === "'") { q = c; continue; }
    if (c === "#" && (i === 0 || /\s/.test(s[i - 1]!))) return s.slice(0, i);
  }
  return s;
}

function scalar(raw: string, n: number): unknown {
  const s = raw.trim();
  if (s === "" || s === "null" || s === "~") return null;
  if (s === "true") return true;
  if (s === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s);
  if (s.startsWith('"')) {
    try { return JSON.parse(s); } catch { throw new Error(`line ${n}: bad double-quoted string`); }
  }
  if (s.startsWith("'")) return s.slice(1, -1).replace(/''/g, "'");
  if (s.startsWith("[")) {
    if (!s.endsWith("]")) throw new Error(`line ${n}: unterminated flow list`);
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    const items: string[] = [];
    let cur = ""; let q: string | null = null;
    for (const c of inner) {
      if (q) { cur += c; if (c === q) q = null; continue; }
      if (c === '"' || c === "'") { q = c; cur += c; continue; }
      if (c === ",") { items.push(cur); cur = ""; continue; }
      cur += c;
    }
    items.push(cur);
    return items.map((x) => scalar(x, n));
  }
  return s;
}

function parseBlock(toks: Tok[], start: number, indent: number): [unknown, number] {
  let i = start;
  if (toks[i]!.text.startsWith("- ") || toks[i]!.text === "-") {
    const list: unknown[] = [];
    while (i < toks.length && toks[i]!.indent === indent && (toks[i]!.text.startsWith("- ") || toks[i]!.text === "-")) {
      const rest = toks[i]!.text.slice(1).trim();
      if (/^[^"'\[]+:(\s|$)/.test(rest)) throw new Error(`line ${toks[i]!.n}: lists of maps are not supported in mock mode`);
      list.push(scalar(rest, toks[i]!.n));
      i++;
    }
    return [list, i];
  }
  const obj: Record<string, unknown> = {};
  while (i < toks.length && toks[i]!.indent === indent) {
    const t = toks[i]!;
    const m = /^("[^"]*"|'[^']*'|[^:]+?)\s*:(?:\s+(.*))?$/.exec(t.text);
    if (!m) throw new Error(`line ${t.n}: expected "key: value"`);
    const rawKey = m[1]!;
    const key = rawKey.startsWith('"') || rawKey.startsWith("'") ? rawKey.slice(1, -1) : rawKey;
    if (key in obj) throw new Error(`line ${t.n}: duplicate key "${key}"`);
    const val = m[2];
    if (val === undefined || val.trim() === "") {
      const next = toks[i + 1];
      if (next && (next.indent > indent || (next.indent === indent && next.text.startsWith("- ")))) {
        const [child, j] = parseBlock(toks, i + 1, next.indent);
        obj[key] = child;
        i = j;
      } else { obj[key] = null; i++; }
    } else { obj[key] = scalar(val, t.n); i++; }
  }
  if (i < toks.length && toks[i]!.indent > indent) throw new Error(`line ${toks[i]!.n}: unexpected indentation`);
  return [obj, i];
}

export function parseYamlLite(text: string): unknown {
  const toks: Tok[] = [];
  text.split(/\r?\n/).forEach((line, idx) => {
    if (line.includes("\t")) throw new Error(`line ${idx + 1}: tabs are not allowed in YAML indentation`);
    const body = stripComment(line).replace(/\s+$/, "");
    if (!body.trim()) return;
    toks.push({ indent: body.length - body.trimStart().length, text: body.trim(), n: idx + 1 });
  });
  if (toks.length === 0) throw new Error("empty document");
  const [v, end] = parseBlock(toks, 0, toks[0]!.indent);
  if (end < toks.length) throw new Error(`line ${toks[end]!.n}: unexpected content`);
  return v;
}

/** Dotted path -> JSON text of the leaf. Lists are leaves. */
export function flatten(v: unknown, prefix = "", out: Record<string, string> = {}): Record<string, string> {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) flatten(x, prefix ? `${prefix}.${k}` : k, out);
  } else out[prefix] = JSON.stringify(v);
  return out;
}

export function diffPaths(before: unknown, after: unknown, max = 20): string[] {
  const a = flatten(before), b = flatten(after);
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  const changed: string[] = [];
  for (const k of keys) if (a[k] !== b[k]) changed.push(k);
  return changed.sort().slice(0, max);
}
