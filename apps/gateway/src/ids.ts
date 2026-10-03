// Sortable ids: 10 chars of base32 time + 16 random. Good enough for ordering audit rows.
const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function newId(): string {
  let t = Date.now(), time = "";
  for (let i = 0; i < 10; i++) { time = B32[t % 32] + time; t = Math.floor(t / 32); }
  const rand = crypto.getRandomValues(new Uint8Array(16));
  let r = "";
  for (const b of rand) r += B32[b % 32];
  return time + r;
}
