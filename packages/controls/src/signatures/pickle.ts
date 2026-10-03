// Minimal pickle opcode walker (SPEC §6.3). Never executes anything: it reads opcodes, records every imported
// global as module.name, and notes whether a call opcode (REDUCE / INST / OBJ / NEWOBJ) follows it.

export interface PickleWalk {
  globals: string[];
  /** Globals followed by a call opcode somewhere later in the stream. */
  called: Set<string>;
  stopped: boolean;
  parseError: string | null;
}

// Argument size for opcodes with a fixed-size argument; "nl" = newline-terminated; "len1"/"len4"/"len8" = length-prefixed.
type Arg = number | "nl" | "nl2" | "len1" | "len4" | "len8";
const OPS: Record<number, Arg> = {};
const def = (chars: string, arg: Arg) => { for (const c of chars) OPS[c.charCodeAt(0)] = arg; };
def("(.012NQRabde}lostu])", 0);
def("FILPSVgp", "nl");
def("ci", "nl2");
def("JjrG", 4); OPS["G".charCodeAt(0)] = 8;
def("Khq", 1);
def("M", 2);
def("TXB", "len4");
def("UC", "len1");
const B = (n: number, arg: Arg) => { OPS[n] = arg; };
B(0x80, 1); B(0x81, 0); B(0x82, 1); B(0x83, 2); B(0x84, 4);
for (const n of [0x85, 0x86, 0x87, 0x88, 0x89, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x97, 0x98]) B(n, 0);
B(0x8a, "len1"); B(0x8b, "len4"); B(0x8c, "len1"); B(0x8d, "len8"); B(0x8e, "len8"); B(0x95, 8); B(0x96, "len8");

const CALLS = new Set(["R".charCodeAt(0), "i".charCodeAt(0), "o".charCodeAt(0), 0x81, 0x92]);
const STRING_OPS = new Set(["X".charCodeAt(0), 0x8c, 0x8d, "V".charCodeAt(0), "S".charCodeAt(0), "U".charCodeAt(0), "T".charCodeAt(0)]);
const MAX_OPS = 200_000;

export function walkPickle(b: Uint8Array): PickleWalk {
  const res: PickleWalk = { globals: [], called: new Set(), stopped: false, parseError: null };
  const strings: string[] = [];
  const memo = new Map<number, string>();
  const pending: string[] = [];
  const dec = new TextDecoder();
  let i = 0;
  const readLine = (): string | null => {
    const nl = b.indexOf(0x0a, i);
    if (nl < 0) return null;
    const s = dec.decode(b.subarray(i, nl));
    i = nl + 1;
    return s;
  };
  const readUint = (n: number): number | null => {
    if (i + n > b.length) return null;
    let v = 0;
    for (let k = n - 1; k >= 0; k--) v = v * 256 + b[i + k]!;
    i += n;
    return v;
  };
  const addGlobal = (g: string) => { res.globals.push(g); pending.push(g); };
  for (let ops = 0; ops < MAX_OPS; ops++) {
    if (i >= b.length) { res.parseError = "truncated: no STOP opcode"; return res; }
    const op = b[i++]!;
    const arg = OPS[op];
    if (arg === undefined) { res.parseError = `unknown opcode 0x${op.toString(16)} at ${i - 1}`; return res; }
    if (op === 0x2e) { res.stopped = true; return res; }
    if (CALLS.has(op) && op !== "i".charCodeAt(0)) { for (const g of pending) res.called.add(g); pending.length = 0; }
    if (op === 0x93) { // STACK_GLOBAL: module and name are the two most recent strings
      const name = strings.pop(), mod = strings.pop();
      if (mod !== undefined && name !== undefined) addGlobal(`${mod}.${name}`);
      continue;
    }
    if (op === 0x94) { const last = strings[strings.length - 1]; if (last !== undefined) memo.set(memo.size, last); continue; }
    if (arg === "nl" || arg === "nl2") {
      const a = readLine();
      const c = arg === "nl2" ? readLine() : "";
      if (a === null || c === null) { res.parseError = "truncated line argument"; return res; }
      if (arg === "nl2") {
        const g = `${a}.${c}`;
        addGlobal(g);
        if (op === "i".charCodeAt(0)) { res.called.add(g); pending.pop(); }
      } else if (STRING_OPS.has(op)) strings.push(a.replace(/^'|'$/g, ""));
      continue;
    }
    if (typeof arg === "number") {
      const v = readUint(arg);
      if (v === null) { res.parseError = "truncated argument"; return res; }
      if (op === "q".charCodeAt(0) || op === "r".charCodeAt(0)) { const last = strings[strings.length - 1]; if (last !== undefined) memo.set(v, last); }
      if (op === "h".charCodeAt(0) || op === "j".charCodeAt(0)) { const s = memo.get(v); if (s !== undefined) strings.push(s); }
      continue;
    }
    const len = readUint(arg === "len1" ? 1 : arg === "len4" ? 4 : 8);
    if (len === null || i + len > b.length) { res.parseError = "truncated length-prefixed argument"; return res; }
    if (STRING_OPS.has(op)) strings.push(dec.decode(b.subarray(i, i + len)));
    i += len;
  }
  res.parseError = "opcode limit reached";
  return res;
}
