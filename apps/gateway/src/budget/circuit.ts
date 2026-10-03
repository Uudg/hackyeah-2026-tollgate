// Upstream circuit breaker (SPEC §5.6): per host, closed → open after N failures in a window → half-open probe.
export type CircuitState = "closed" | "open" | "half_open";

interface HostState { state: CircuitState; failures: number[]; openedAt: number; probing: boolean }

export class CircuitBreaker {
  private hosts = new Map<string, HostState>();
  constructor(private onChange: (host: string, state: CircuitState) => void) {}

  private get(host: string): HostState {
    let h = this.hosts.get(host);
    if (!h) { h = { state: "closed", failures: [], openedAt: 0, probing: false }; this.hosts.set(host, h); }
    return h;
  }

  private set(host: string, h: HostState, state: CircuitState) {
    if (h.state === state) return;
    h.state = state;
    this.onChange(host, state);
  }

  /**
   * Stage 2, fail fast: null = the request may go on; otherwise seconds until the next probe. Moves open → half-open
   * once openForMs has passed, but does not take the probe slot: a request blocked later (tier 0, budget, dry run)
   * never reaches the upstream and would otherwise hold the slot forever.
   */
  check(host: string, openForMs: number): number | null {
    const h = this.get(host);
    if (h.state === "closed") return null;
    const elapsed = Date.now() - h.openedAt;
    if (h.state === "open" && elapsed >= openForMs) this.set(host, h, "half_open");
    if (h.state === "half_open" && !h.probing) return null;
    return Math.max(1, Math.ceil((openForMs - elapsed) / 1000));
  }

  /** Right before the upstream call: same answer as check(), and in half-open the first caller takes the probe slot. */
  claim(host: string, openForMs: number): number | null {
    const retry = this.check(host, openForMs);
    if (retry !== null) return retry;
    const h = this.get(host);
    if (h.state === "half_open") h.probing = true;
    return null;
  }

  success(host: string): void {
    const h = this.get(host);
    h.failures = [];
    h.probing = false;
    this.set(host, h, "closed");
  }

  failure(host: string, threshold: number, windowMs: number): void {
    const h = this.get(host);
    const now = Date.now();
    h.probing = false;
    if (h.state === "half_open") { h.openedAt = now; this.set(host, h, "open"); return; }
    h.failures = [...h.failures.filter((t) => now - t < windowMs), now];
    if (h.failures.length >= threshold) { h.openedAt = now; this.set(host, h, "open"); }
  }

  states(): Array<{ host: string; state: CircuitState }> {
    return [...this.hosts].map(([host, h]) => ({ host, state: h.state }));
  }

  reset(): void { this.hosts.clear(); }
}
