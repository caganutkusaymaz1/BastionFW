export type SecuritySeverity = "critical" | "high" | "medium";

export type DetectionRequest = {
  ip: string;
  userAgent?: string;
  uri: string;
  body?: string;
};

export type DetectionHit = {
  rule: "sqli" | "xss" | "path_traversal" | "web_shell" | "command_injection";
  severity: SecuritySeverity;
  score: number;
  evidence: string;
};

const signatures: Array<{
  rule: DetectionHit["rule"];
  severity: SecuritySeverity;
  score: number;
  pattern: RegExp;
  evidence: string;
}> = [
  {
    rule: "sqli",
    severity: "critical",
    score: 5,
    pattern: /\bunion\s+(?:all\s+)?select\b|\b(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|\bsleep\s*\(|\bbenchmark\s*\(/i,
    evidence: "SQL injection operator or time-delay signature",
  },
  {
    rule: "xss",
    severity: "high",
    score: 4,
    pattern: /<\s*script\b|javascript\s*:|on(?:error|load|mouseover)\s*=|<\s*svg\b/i,
    evidence: "script or inline event-handler signature",
  },
  {
    rule: "path_traversal",
    severity: "high",
    score: 4,
    pattern: /(?:\.\.\/|\.\.\\)|\/etc\/passwd|\/proc\/self\/environ|boot\.ini/i,
    evidence: "decoded path traversal or sensitive file signature",
  },
  {
    rule: "web_shell",
    severity: "critical",
    score: 5,
    pattern: /\b(?:eval|assert|system|shell_exec|passthru|base64_decode)\s*\(/i,
    evidence: "server-side execution or web-shell signature",
  },
  {
    rule: "command_injection",
    severity: "critical",
    score: 5,
    pattern: /(?:^|[;&|])\s*(?:id|whoami|uname|curl|wget|nc|cat)\b|\$\([^)]{1,120}\)/i,
    evidence: "shell separator or command substitution signature",
  },
];

export function normalizePayload(value: string) {
  let decoded = value;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded.replace(/\s+/g, " ").trim();
}

export function detectWebThreats(request: DetectionRequest): DetectionHit[] {
  const payload = normalizePayload(
    [request.uri, request.userAgent ?? "", request.body ?? ""].join(" "),
  );
  return signatures
    .filter((signature) => signature.pattern.test(payload))
    .map(({ rule, severity, score, evidence }) => ({
      rule,
      severity,
      score,
      evidence,
    }));
}

export class SlidingWindowLimiter {
  private readonly buckets = new Map<string, number[]>();

  constructor(
    private readonly maxRequests: number,
    private readonly windowMs: number,
  ) {}

  allow(key: string, now = Date.now()) {
    const cutoff = now - this.windowMs;
    const bucket = (this.buckets.get(key) ?? []).filter((stamp) => stamp > cutoff);
    if (bucket.length >= this.maxRequests) {
      this.buckets.set(key, bucket);
      return false;
    }
    bucket.push(now);
    this.buckets.set(key, bucket);
    return true;
  }

  purge(now = Date.now()) {
    const cutoff = now - this.windowMs;
    for (const [key, bucket] of this.buckets) {
      const next = bucket.filter((stamp) => stamp > cutoff);
      if (next.length === 0) this.buckets.delete(key);
      else this.buckets.set(key, next);
    }
  }
}

export class TokenBucketLimiter {
  private readonly buckets = new Map<string, { tokens: number; updatedAt: number }>();

  constructor(
    private readonly capacity: number,
    private readonly refillPerSecond: number,
  ) {}

  allow(key: string, cost = 1, now = Date.now()) {
    const previous = this.buckets.get(key) ?? { tokens: this.capacity, updatedAt: now };
    const elapsedSeconds = Math.max(0, now - previous.updatedAt) / 1000;
    const tokens = Math.min(this.capacity, previous.tokens + elapsedSeconds * this.refillPerSecond);
    if (tokens < cost) {
      this.buckets.set(key, { tokens, updatedAt: now });
      return false;
    }
    this.buckets.set(key, { tokens: tokens - cost, updatedAt: now });
    return true;
  }
}