/**
 * Typed client for the Python BastionFW dashboard API.
 *
 * The Express service is deliberately a thin proxy in front of the real
 * Python engine: it never fabricates operational data. Every request is
 * authenticated with the shared `ED_BT_ADE_DASHBOARD_TOKEN` bearer token and
 * all read/action payloads originate from `bastionfw` (dashboard.py).
 */
import { createHash } from "node:crypto";

const BASTIONFW_DASHBOARD_URL = (
  process.env["BASTIONFW_DASHBOARD_URL"] ?? "http://127.0.0.1:8080"
).replace(/\/+$/, "");

const BASTIONFW_DASHBOARD_TOKEN = process.env["ED_BT_ADE_DASHBOARD_TOKEN"] ?? "";

export class BastionUnavailableError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "BastionUnavailableError";
  }
}

export function isDashboardConfigured(): boolean {
  return BASTIONFW_DASHBOARD_TOKEN.length > 0;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!isDashboardConfigured()) {
    throw new BastionUnavailableError(
      "ED_BT_ADE_DASHBOARD_TOKEN is not configured; the BastionFW dashboard " +
        "cannot be reached.",
      503,
    );
  }
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  headers.set("Authorization", `Bearer ${BASTIONFW_DASHBOARD_TOKEN}`);
  headers.set("Cache-Control", "no-store");
  let response: Response;
  try {
    response = await fetch(`${BASTIONFW_DASHBOARD_URL}${path}`, {
      ...init,
      headers,
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new BastionUnavailableError(
      `BastionFW dashboard at ${BASTIONFW_DASHBOARD_URL} is unreachable.`,
      502,
    );
  }
  if (!response.ok) {
    throw new BastionUnavailableError(
      `BastionFW dashboard responded ${response.status} for ${path}.`,
      502,
    );
  }
  return (await response.json()) as T;
}

// ---------------------------------------------------------------------------
// Snapshot shape (mirrors sentinel.Sentinel.dashboard_snapshot)
// ---------------------------------------------------------------------------

export type SnapshotMode = "ENFORCING" | "DRY-RUN";
export type SnapshotSeverity = "critical" | "high" | "medium" | "low";

export interface SnapshotAlert {
  timestamp: number;
  rule: string;
  severity: SnapshotSeverity;
  source: string;
  ip: string | null;
  evidence: string;
}

export interface SnapshotSource {
  name: string;
  path: string;
  source_type?: string;
}

export interface SnapshotService {
  name: string;
  state: "running" | "stopped" | "degraded";
  detail: string;
}

export interface SnapshotThreatIntel {
  enabled: boolean;
  provider: string;
  status: "healthy" | "degraded" | "disabled";
  started_at: number;
}

export interface SnapshotWaf {
  enabled: boolean;
  mode: "detect" | "block";
  engine_mode: "detect" | "block";
  deadman_tripped: boolean;
  requests_blocked: number;
  rule_matches: number;
  top_rules: Array<{ rule_id: string; count: number }>;
}

export interface BastionSnapshot {
  project: string;
  developer: string;
  ready: boolean;
  mode: SnapshotMode;
  uptime_seconds: number;
  queue_depth: number;
  logs_processed: number;
  threats_detected: number;
  ips_blocked: number;
  pipeline_errors: number;
  pipeline_latency_seconds: number;
  protected_sources: number;
  blocked_addresses: string[];
  sources: SnapshotSource[];
  services: SnapshotService[];
  threat_intel: SnapshotThreatIntel;
  waf: SnapshotWaf;
  alerts: SnapshotAlert[];
}

export interface BastionActionResult {
  ok: boolean;
  message: string;
  mode: SnapshotMode;
}

export async function fetchStatus(): Promise<BastionSnapshot> {
  return request<BastionSnapshot>("/api/status");
}

export async function fetchMetricsText(): Promise<string> {
  return request<string>("/api/metrics");
}

export async function postBanAction(
  action: "ban" | "unban",
  ip: string,
  durationSeconds?: number,
): Promise<BastionActionResult> {
  return request<BastionActionResult>("/api/bans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(
      durationSeconds === undefined
        ? { action, ip }
        : { action, ip, duration: durationSeconds },
    ),
  });
}

// ---------------------------------------------------------------------------
// Snapshot -> operations-model transforms (no fabricated numbers)
// ---------------------------------------------------------------------------

const RULE_PRESENTATION: Record<string, { label: string; color: string }> = {
  ssh_brute_force: { label: "Brute force", color: "#fb923c" },
  web_attack: { label: "Web attack", color: "#f87171" },
  coraza_waf: { label: "WAF / CRS", color: "#38bdf8" },
  http_rate_limit: { label: "Rate limit", color: "#facc15" },
  privilege_escalation_anomaly: { label: "Privilege", color: "#a78bfa" },
};

export function attackCountsFrom(snapshot: BastionSnapshot): Array<{
  label: string;
  count: number;
  color: string;
}> {
  const counts = new Map<string, number>();
  for (const alert of snapshot.alerts) {
    counts.set(alert.rule, (counts.get(alert.rule) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1])
    .slice(0, 8)
    .map(([rule, count]) => {
      const presentation = RULE_PRESENTATION[rule] ?? { label: rule };
      return {
        label: presentation.label ?? rule,
        count,
        color: presentation.color ?? "#8ea6c1",
      };
    });
}

export function eventIdFor(alert: SnapshotAlert, index: number): string {
  const digest = createHash("sha1")
    .update(`${alert.timestamp}:${alert.rule}:${alert.source}:${alert.ip ?? ""}`)
    .digest("hex")
    .slice(0, 12);
  return `evt-${digest}-${index}`;
}

export function liveEventsPerMinute(snapshot: BastionSnapshot): number {
  const cutoff = (Date.now() / 1000) - 60;
  return snapshot.alerts.filter((alert) => alert.timestamp >= cutoff).length;
}

export function snapshotThreatIntel(snapshot: BastionSnapshot) {
  const startedAt = new Date(snapshot.threat_intel.started_at * 1000);
  return {
    status: snapshot.threat_intel.status,
    lastRefresh: Number.isNaN(startedAt.getTime()) ? new Date() : startedAt,
    provider: snapshot.threat_intel.provider || "AbuseIPDB",
  };
}
