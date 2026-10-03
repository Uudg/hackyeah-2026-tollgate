// E-mail addresses (SPEC §7.1). The TLD must have at least two letters.
// The lookbehind makes a match start only where a local-part run starts (linear on long "a.a.a." runs).
export const EMAIL_RE = /(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;

// Obfuscated addresses: "jan.kowalski [at] example [dot] com", "jan(at)example.com". The "at" must be in brackets and
// the address must end in a dot (bracketed or plain) and a TLD of 2+ letters, so prose like "meet (at) noon" is not one.
const DOT = String.raw`(?:\s*[\[(]\s*dot\s*[\])]\s*|\.)`;
export const EMAIL_OBFUSCATED_RE = new RegExp(String.raw`(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+\s*[\[(]\s*at\s*[\])]\s*[A-Z0-9-]+(?:${DOT}[A-Z0-9-]+)*${DOT}[A-Z]{2,}\b`, "gi");
