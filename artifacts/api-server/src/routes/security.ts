import { Router, type IRouter } from "express";
import { isIP } from "node:net";
import {
  BanAddressBody,
  BanAddressResponse,
  ControlServiceBody,
  ControlServiceResponse,
  GetSecurityOverviewResponse,
  ListSecurityEventsQueryParams,
  ListSecurityEventsResponse,
  RefreshThreatIntelResponse,
  UnbanAddressBody,
  UnbanAddressResponse,
} from "@workspace/api-zod";
import { requireAuth } from "../middlewares/requireAuth";

const router: IRouter = Router();
const mode = "DRY-RUN" as const;

type Event = {
  id: string;
  timestamp: string;
  severity: "critical" | "high" | "medium" | "low";
  rule: string;
  source: string;
  ip: string;
  evidence: string;
  status: "blocked" | "observed" | "mitigated";
};

const events: Event[] = [
  {
    id: "evt-7f2a",
    timestamp: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
    severity: "critical",
    rule: "web_attack",
    source: "nginx/access.log",
    ip: "185.220.101.42",
    evidence: "union select detected in request query",
    status: "blocked",
  },
  {
    id: "evt-7f29",
    timestamp: new Date(Date.now() - 1000 * 60 * 7).toISOString(),
    severity: "high",
    rule: "ssh_brute_force",
    source: "auth.log",
    ip: "45.148.10.91",
    evidence: "14 failed attempts / 60s",
    status: "blocked",
  },
  {
    id: "evt-7f28",
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    severity: "high",
    rule: "lfi_path_traversal",
    source: "nginx/access.log",
    ip: "91.240.118.172",
    evidence: "encoded traversal reached /etc/passwd",
    status: "mitigated",
  },
  {
    id: "evt-7f27",
    timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    severity: "medium",
    rule: "xss",
    source: "nginx/access.log",
    ip: "103.41.12.8",
    evidence: "inline event handler in request payload",
    status: "observed",
  },
  {
    id: "evt-7f26",
    timestamp: new Date(Date.now() - 1000 * 60 * 24).toISOString(),
    severity: "medium",
    rule: "command_injection",
    source: "nginx/access.log",
    ip: "172.104.31.6",
    evidence: "shell separator followed by uname",
    status: "blocked",
  },
];

const blockedAddresses = new Set(["185.220.101.42", "45.148.10.91"]);
const serviceStates = new Map<string, "running" | "stopped" | "degraded">([
  ["sentinel", "running"],
  ["firewall", "running"],
  ["threat-intel", "degraded"],
]);

function overview() {
  return GetSecurityOverviewResponse.parse({
    ready: true,
    mode,
    uptimeSeconds: 18_420,
    queueDepth: 37,
    logsProcessed: 1_284_921,
    threatsDetected: 842,
    ipsBlocked: blockedAddresses.size,
    pipelineErrors: 2,
    eventsPerMinute: 126,
    protectedSources: 4,
    attackCounts: [
      { label: "SQLi", count: 312, color: "#f87171" },
      { label: "Brute force", count: 241, color: "#fb923c" },
      { label: "Traversal", count: 157, color: "#facc15" },
      { label: "XSS", count: 89, color: "#a78bfa" },
      { label: "Command", count: 43, color: "#38bdf8" },
    ],
    traffic: [
      { label: "00:00", requests: 72, blocked: 12 },
      { label: "04:00", requests: 44, blocked: 8 },
      { label: "08:00", requests: 126, blocked: 22 },
      { label: "12:00", requests: 98, blocked: 18 },
      { label: "16:00", requests: 184, blocked: 41 },
      { label: "20:00", requests: 148, blocked: 26 },
      { label: "Now", requests: 216, blocked: 54 },
    ],
    blockedAddresses: Array.from(blockedAddresses),
    threatIntel: {
      status: "degraded",
      lastRefresh: new Date(Date.now() - 1000 * 60 * 11).toISOString(),
      provider: "AbuseIPDB adapter",
    },
    services: [
      {
        name: "sentinel",
        state: serviceStates.get("sentinel"),
        detail: "4 log sources protected",
      },
      {
        name: "firewall",
        state: serviceStates.get("firewall"),
        detail: mode === "DRY-RUN" ? "Staging rules only" : "nftables active",
      },
      {
        name: "threat-intel",
        state: serviceStates.get("threat-intel"),
        detail: "Provider circuit half-open",
      },
    ],
  });
}

function action(message: string) {
  return { ok: true, message, mode };
}

router.use(requireAuth);

router.get("/overview", (_req, res) => {
  res.json(overview());
});

router.get("/events", (req, res) => {
  const parsed = ListSecurityEventsQueryParams.safeParse({
    limit: req.query.limit,
    severity: req.query.severity,
  });
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid event query." });
    return;
  }
  const query = parsed.data;
  const result = events
    .filter((event) => !query.severity || event.severity === query.severity)
    .slice(0, query.limit ?? 20);
  res.json(ListSecurityEventsResponse.parse(result));
});

router.post("/actions/ban", (req, res) => {
  const parsed = BanAddressBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "A valid IP address is required." });
    return;
  }
  const body = parsed.data;
  const ip = body.ip.trim();
  if (!isPublicAddress(ip)) {
    res.status(400).json({ error: "Only public IP addresses can be staged." });
    return;
  }
  blockedAddresses.add(ip);
  res.json(BanAddressResponse.parse(action(`Ban staged for ${ip} in dry-run mode.`)));
});

router.post("/actions/unban", (req, res) => {
  const parsed = UnbanAddressBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "A valid IP address is required." });
    return;
  }
  const body = parsed.data;
  const ip = body.ip.trim();
  if (!isPublicAddress(ip)) {
    res.status(400).json({ error: "Only public IP addresses can be staged." });
    return;
  }
  blockedAddresses.delete(ip);
  res.json(UnbanAddressResponse.parse(action(`Unban staged for ${ip} in dry-run mode.`)));
});

router.post("/actions/threat-intel", (_req, res) => {
  res.json(
    RefreshThreatIntelResponse.parse(
      action("Threat intelligence refresh queued; provider remains isolated from ingestion."),
    ),
  );
});

router.post("/actions/service", (req, res) => {
  const parsed = ControlServiceBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "A valid service action is required." });
    return;
  }
  const body = parsed.data;
  const current = serviceStates.get(body.service) ?? "stopped";
  const next = body.action === "stop" ? "stopped" : "running";
  serviceStates.set(body.service, next);
  const verb = body.action === "restart" ? "Restart queued" : `${body.action} requested`;
  res.json(
    ControlServiceResponse.parse(
      action(`${verb} for ${body.service}; state ${current} → ${next} in dry-run mode.`),
    ),
  );
});

function isPublicAddress(value: string) {
  // Reuse the Python-side policy via Node: accept only true global unicast
  // addresses. The previous hand-rolled prefix checks missed link-local
  // 169.254.0.0/16, CGNAT 100.64.0.0/10, and IPv4-mapped ::ffff:a.b.c.d
  // forms — all of which could stage a "public" ban against infrastructure.
  const family = isIP(value);
  if (family === 4) {
    const parts = value.split(".");
    if (parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part))) return false;
    const numbers = parts.map(Number);
    if (numbers.some((part) => part < 0 || part > 255)) return false;
    const [a, b] = numbers;
    return !(a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a >= 224));
  }
  if (family !== 6) return false;
  const lower = value.toLowerCase();
  if (lower.startsWith("::ffff:")) return false; // IPv4-mapped IPv6
  return lower !== "::" && lower !== "::1" &&
    !lower.startsWith("fc") && !lower.startsWith("fd") &&
    !lower.startsWith("fe8") && !lower.startsWith("fe9") &&
    !lower.startsWith("fea") && !lower.startsWith("feb") &&
    !lower.startsWith("ff") &&
    !lower.startsWith("64:ff9b:") && // RFC 6052 NAT64 translation prefix
    !lower.startsWith("::ffff:0:");
}

export default router;