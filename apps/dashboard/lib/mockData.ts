// Static fixtures for mock mode: a policy.yaml that mirrors the shape of the repo's ./policy.yaml, and a signature feed.
// Keys are obviously fake; they are not the demo keys from the real policy.yaml.
import type { SignatureEntry } from "@tollgate/policy";

export const MOCK_POLICY_YAML = `# Tollgate control catalog (MOCK COPY: gateway not connected)
# Edit a value, press Validate, then Save. In mock mode the dashboard applies the change locally
# and shows the same toasts the live gateway would send (policy.loaded / policy.rejected).

version: 12            # human-readable counter; the content hash is the real identity
mode: enforce          # enforce | monitor (monitor records "would block" and forwards unchanged)

upstream:
  base_url: http://127.0.0.1:11434/v1
  timeout_ms: 60000

agents:
  demo-agent:
    key: tg_demo-agent_MOCKKEYdemo000001
    scopes: [chat, tools, dry_run]
    description: "Customer-support assistant for a retail bank"
  research-bot:
    key: tg_research-bot_MOCKKEYresearch01
    scopes: [chat]
    description: "Read-only research assistant"
  finance-agent:
    key: tg_finance-agent_MOCKKEYfinance001
    scopes: [chat, tools]
    models: ["llama3.2:3b"]
    description: "Payments assistant, strict budget"
  test-small-budget:
    key: tg_test-small-budget_MOCKKEYsmall000001
    scopes: [chat]
  redteam:
    key: tg_redteam_MOCKKEYredteam0001
    scopes: [chat, tools, dry_run]

models:
  allow:
    - "llama3.2:3b"
    - "llama3.2:*"
    - "qwen2.5:*"
    - "llama-guard3:1b"
  deny_registries: ["*"]

controls:
  pii:
    enabled: true
    action: redact                 # redact | block
    entities: [email, phone, iban, card, pesel]
  secrets:
    enabled: true
    action: block
    entropy_min: 3.5
    entropy_min_len: 32
  unicode:
    enabled: true
    action: block
    max_invisible: 3
    max_homoglyphs: 3
  decode:
    enabled: true
    action: block
    max_depth: 2
  prompt_injection:
    enabled: true
    action: block
    threshold: 0.8                 # tier-1 score at or above which the action applies
    heuristics: true
  content_safety:
    enabled: true
    action: block
    categories: [S1, S2, S9, S11]
  canaries:
    enabled: true
    action: kill_session
  link_exfil:
    enabled: true
    action: redact
    allow_domains: [intranet.example.com, docs.example.com, github.com]
    min_query_len: 20
    block_images: true
  sysprompt:
    enabled: true
    action: redact
    ngram: 8
    overlap_threshold: 0.2
    min_run: 12
  tool_calls:
    enabled: true
    action: block
    allow: ["*"]
    deny: ["delete_*", "drop_*", "shell", "exec"]
    require_approval: ["send_email", "transfer_funds", "update_*"]
    approval_timeout_ms: 30000
    max_arguments_bytes: 16384
  signatures:
    enabled: true
    action: block
    feed: ./feeds/ai-exploits.json
    refresh: 60s
    fail_mode: open

semantic:
  enabled: true
  provider: local
  fail_mode: open                  # open | closed when the classifier times out
  classifier_model: llama-guard3:1b
  judge_model: llama3.2:3b
  timeout_ms: 1500
  judge_timeout_ms: 6000
  judge_min_confidence: 0.6
  uncertain_band: [0.3, 0.8]

budgets:
  default_max_tokens: 1024
  enforce_in_monitor: false
  default:
    tokens_per_hour: 50000
    usd_per_day: 2
    compute_seconds_per_hour: 600
    max_tool_depth: 8
    requests_per_minute: 120
  agents:
    research-bot:
      tokens_per_hour: 200000
      requests_per_minute: 300
    finance-agent:
      tokens_per_hour: 20000
      usd_per_day: 1
    test-small-budget:
      tokens_per_hour: 6000
      requests_per_minute: 10
  loop_breaker:
    enabled: true
    same_request_within: 30s
    max_repeats: 5
    action: block
  circuit_breaker:
    enabled: true
    failure_threshold: 5
    window: 30s
    open_for: 20s

canaries:
  auto_generate: 3

telemetry:
  reservoir_size: 2000
  sse_heartbeat_ms: 15000
  log_level: info
`;

const E = (
  id: string, title: string, cve: string | null, type: SignatureEntry["type"], pattern: unknown,
  scope: SignatureEntry["scope"], severity: SignatureEntry["severity"], action: SignatureEntry["action"],
  owasp: string[], description: string, references: string[], published?: string, enabled = true,
): SignatureEntry =>
  ({ id, title, cve, type, pattern, scope, severity, action, owasp, description, references, published, enabled }) as SignatureEntry;

export const MOCK_FEED: SignatureEntry[] = [
  E("jfrog-hf-pickle-rce-2024", "Malicious Hugging Face models: pickle __reduce__ reverse shell (JFrog, Feb 2024)", null, "pickle-opcode",
    { dangerous_globals: ["os.system", "subprocess.Popen", "builtins.exec", "builtins.eval", "socket.socket"], require_reduce: true, on_parse_error: "allow" },
    ["request", "tool_call", "model_file"], "critical", "block", ["LLM03", "LLM04", "ASI04", "ASI05"],
    "Base64 blobs that decode to a pickle stream calling a dangerous global through __reduce__.",
    ["https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/"], "2024-02-27"),
  E("nullifai-broken-pickle-2025", "nullifAI: broken pickle evades Picklescan (ReversingLabs, Jan 2025)", null, "pickle-opcode",
    { dangerous_globals: ["os.system", "subprocess.Popen"], require_reduce: false, on_parse_error: "block", allowed_container_magic: ["504b0304"] },
    ["model_file", "request"], "critical", "block", ["LLM03", "ASI04", "ASI05"],
    "Pickle streams that stop early or sit in an unexpected container are treated as hostile.",
    ["https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face"], "2025-02-06"),
  E("shadowray-cve-2023-48022", "ShadowRay: unauthenticated Ray Jobs API", "CVE-2023-48022", "url-pattern",
    { port: 8265, path_regex: "^/api/(jobs|version|cluster_status|packages)", scheme: ["http", "https"] },
    ["tool_call", "request"], "critical", "block", ["ASI02", "ASI05", "ASI03"],
    "A tool call or message pointing at port 8265 /api/jobs on a Ray head node.",
    ["https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild"], "2024-03-26"),
  E("probllama-cve-2024-37032-digest", "Probllama: path traversal via digest field in Ollama /api/pull", "CVE-2024-37032", "regex",
    { regex: "(\\\"digest\\\"\\\\s*:\\\\s*\\\"(?!sha256:[a-f0-9]{64}\\\")[^\\\"]*\\\")", flags: "i" },
    ["request", "tool_call", "response"], "critical", "block", ["LLM03", "ASI04", "ASI05"],
    "A manifest whose digest is not a plain sha256 hash, or a pull URL containing ../.",
    ["https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032"], "2024-06-24"),
  E("probllama-cve-2024-37032-version", "Probllama: Ollama versions before 0.1.34 are vulnerable", "CVE-2024-37032", "version-range",
    { component: "ollama", lt: "0.1.34" }, ["upstream"], "high", "allow", ["LLM03", "ASI04"],
    "Reporting signal only: compared with GET /api/version on the upstream at startup and on every reload.",
    ["https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032"], "2024-06-24"),
  E("echoleak-cve-2025-32711", "EchoLeak: zero-click exfiltration through markdown images (M365 Copilot)", "CVE-2025-32711", "url-pattern",
    { query_min_len: 20, markdown_image: true, scheme: ["http", "https"] },
    ["response", "tool_call"], "high", "redact", ["LLM01", "LLM02", "LLM05", "ASI01"],
    "A markdown image with a long query string to a host that is not on link_exfil.allow_domains.",
    ["https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html"], "2025-06-11"),
  E("mcp-tool-poisoning-2025", "MCP tool poisoning: hidden instructions in tool descriptions", "CVE-2025-54136", "tool-description",
    { regex: "(<\\\\s*important\\\\s*>|do not (tell|mention) (the )?user|~/\\\\.ssh|id_rsa)", flags: "i", max_length: 2000, invisible_chars: true, html_comments: true },
    ["tool_definition"], "high", "block", ["LLM01", "LLM03", "ASI01", "ASI02", "ASI04"],
    "Instruction-like text, invisible characters or HTML comments inside tools[].function.description.",
    ["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"], "2025-04-01"),
  E("generic-shell-exec-code", "Generic: shell execution one-liners in code blocks", null, "regex",
    { regex: "(curl|wget)[^\\n|]*\\\\|\\\\s*(ba)?sh", flags: "i" }, ["request", "response", "tool_call"], "high", "block", ["LLM05", "ASI05"],
    "Pipe-to-shell installers inside messages or tool arguments.", ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"]),
  E("generic-ssrf-cloud-metadata", "Generic: cloud metadata endpoints in tool arguments", null, "regex",
    { regex: "169\\\\.254\\\\.169\\\\.254|metadata\\\\.google\\\\.internal", flags: "i" }, ["tool_call", "request"], "high", "block", ["LLM06", "ASI02"],
    "SSRF toward instance metadata services.", ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"]),
  E("generic-jailbreak-families", "Generic: named jailbreak families (DAN, developer mode)", null, "regex",
    { regex: "\\\\b(DAN mode|developer mode enabled|jailbroken)\\\\b", flags: "i" }, ["request"], "medium", "block", ["LLM01", "ASI01"],
    "Fixed phrases from public jailbreak collections.", ["https://github.com/NVIDIA/garak"], undefined, false),
];
