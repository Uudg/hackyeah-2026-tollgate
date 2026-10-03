// `regex` entries (SPEC §6.3): compiled once per feed load, run on every text variant in the entry's scopes.
export function compileRegex(src: string, flags: string | undefined): RegExp {
  return new RegExp(src, (flags ?? "").replace(/g/g, ""));
}
