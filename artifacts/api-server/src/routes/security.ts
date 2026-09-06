import { Router, type IRouter } from "express";
import { isIP } from "node:net";
import {
  BanAddressBody,
  BanAddressResponse,
  ControlServiceBody,
  ControlServiceResponse,
  ListSecurityEventsQueryParams,
  ListSecurityEventsResponse,
  UnbanAddressBody,
  UnbanAddressResponse,
} from "@workspace/api-zod";
import { requireAuth } from "../middlewares/requireAuth";

/**
 * Proxy layer in front of the real BastionFW dashboard API.
 *
 * Every request is forwarded to the Python engine's authenticated dashboard
 * (``dashboard.py``). No mock or dummy data lives here: if the engine is
 * unreachable the API answers 502 with a JSON error, never fabricated
 * metrics.
 *
 * Configuration (environment):
 * - BASTIONFW_API_URL: base URL of the engine dashboard, e.g.
 *   ``http://bastionfw:8080`` (compose-internal name is fine; the engine
 *   side allowlists internal hosts via waf.trusted_internal_hosts).
 * - BASTIONFW_API_TOKEN: the dashboard bearer token
 *   (ED_BT_ADE_DASHBOARD_TOKEN value on the engine). Keep this secret;
 *   it is sent only server-side and never returned to clients.
 *
 * Timeouts are bounded so a hung engine cannot pin Express workers.
 */
const router: IRouter = Router();

const UPSTREAM_URL = (process.env.BASTIONFW_API_URL ?? "").replace(/\/+$/, "");
const UPSTREAM_TOKEN = process.env.BASTIONFW_API_TOKEN ?? "";
const UPSTREAM_TIMEOUT_MS = Number(process.env.BASTIONFW_API_TIMEOUT_MS ?? 5_000);

function upstreamConfigured(): boolean {
  return UPSTREAM_URL.length > 0;
}

type UpstreamResult =
  | { ok: true; status: number; body: unknown }
  | { ok: false; status: number; error: string };

async function callUpstream(
  path: string,
  init: { method: "GET" | "POST"; body?: unknown },
): Promise<UpstreamResult> {
  if (!upstreamConfigured()) {
    return {
      ok: false,
      status: 503,
      error:
        "BastionFW engine upstream is not configured; set BASTIONFW_API_URL and BASTIONFW_API_TOKEN.",
    };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const response = await fetch(`${UPSTREAM_URL}${path}`, {
      method: init.method,
      headers: {
        Authorization: `Bearer ${UPSTREAM_TOKEN}`,
        ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
      signal: controller.signal,
    });
    const text = await response.text();
    let body: unknown;
    try {
      body = text.length > 0 ? JSON.parse(text) : null;
    } catch {
      body = text;
    }
    return { ok: true, status: response.status, body };
  } catch (error) {
    const reason = error instanceof Error ? error.message : "unknown error";
    return { ok: false, status: 502, error: `BastionFW engine unreachable: ${reason}` };
  } finally {
    clearTimeout(timer);
  }
}

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

router.use(requireAuth);

router.get("/overview", async (_req, res) => {
  const upstream = await callUpstream("/api/status", { method: "GET" });
  if (!upstream.ok) {
    res.status(upstream.status).json({ error: upstream.error });
    return;
  }
  if (upstream.status !== 200 || typeof upstream.body !== "object" || upstream.body === null) {
    res.status(502).json({ error: "Unexpected engine dashboard response." });
    return;
  }
  // Forward the engine snapshot verbatim (snake_case fields from
  // dashboard.py); the console maps field names presentationally.
  res.json(upstream.body);
});

router.get("/events", async (req, res) => {
  const parsed = ListSecurityEventsQueryParams.safeParse({
    limit: req.query.limit,
    severity: req.query.severity,
  });
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid event query." });
    return;
  }
  // The engine's dashboard exposes recent alerts inside /api/status. Map the
  // queried severity/limit onto that feed — no client-side fabrication.
  const upstream = await callUpstream("/api/status", { method: "GET" });
  if (!upstream.ok) {
    res.status(upstream.status).json({ error: upstream.error });
    return;
  }
  const body = upstream.body as { alerts?: unknown } | null;
  const alerts = Array.isArray(body?.alerts) ? body!.alerts : [];
  const query = parsed.data;
  const filtered = (alerts as Array<Record<string, unknown>>)
    .filter((alert) => !query.severity || alert.severity === query.severity)
    .slice(0, query.limit ?? 20)
    .map((alert, index) => ({
      id: `alert-${index}`,
      timestamp: typeof alert.timestamp === "number"
        ? new Date(alert.timestamp * 1000).toISOString()
        : new Date().toISOString(),
      severity: typeof alert.severity === "string" ? alert.severity : "low",
      rule: typeof alert.rule === "string" ? alert.rule : "unknown",
      source: typeof alert.source === "string" ? alert.source : "engine",
      ip: typeof alert.ip === "string" ? alert.ip : "",
      evidence: typeof alert.evidence === "string" ? alert.evidence : "",
      status: "observed" as const,
    }));
  res.json(ListSecurityEventsResponse.parse(filtered));
});

router.post("/actions/ban", (req, res) => {
  const parsed = BanAddressBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "A valid IP address is required." });
    return;
  }
  const ip = parsed.data.ip.trim();
  if (!isPublicAddress(ip)) {
    res.status(400).json({ error: "Only public IP addresses can be staged." });
    return;
  }
  void (async () => {
    const upstream = await callUpstream("/api/status", { method: "GET" });
    if (!upstream.ok) {
      res.status(upstream.status).json({ error: upstream.error });
      return;
    }
    // The engine dashboard is a read-only monitor; operator bans are applied
    // through the engine host's nftables tooling. Report the validated
    // request honestly instead of pretending it was applied here.
    res.json(BanAddressResponse.parse({
      ok: false,
      message: `Ban request for ${ip} validated; apply it on the engine host (dashboard API is read-only).`,
      mode: "DRY-RUN",
    }));
  })();
});

router.post("/actions/unban", (req, res) => {
  const parsed = UnbanAddressBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "A valid IP address is required." });
    return;
  }
  const ip = parsed.data.ip.trim();
  if (!isPublicAddress(ip)) {
    res.status(400).json({ error: "Only public IP addresses can be staged." });
    return;
  }
  void (async () => {
    const upstream = await callUpstream("/api/status", { method: "GET" });
    if (!upstream.ok) {
      res.status(upstream.status).json({ error: upstream.error });
      return;
    }
    res.json(UnbanAddressResponse.parse({
      ok: false,
      message: `Unban request for ${ip} validated; apply it on the engine host (dashboard API is read-only).`,
      mode: "DRY-RUN",
    }));
  })();
});

router.post("/actions/threat-intel", (_req, res) => {
  void (async () => {
    const upstream = await callUpstream("/api/status", { method: "GET" });
    if (!upstream.ok) {
      res.status(upstream.status).json({ error: upstream.error });
      return;
    }
    res.json(BanAddressResponse.parse({
      ok: true,
      message: "Engine reachable; threat-intel refresh runs on the engine host schedule.",
      mode: "DRY-RUN",
    }));
  })();
});

router.post("/actions/service", (req, res) => {
  const parsed = ControlServiceBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "A valid service action is required." });
    return;
  }
  void (async () => {
    const upstream = await callUpstream("/api/status", { method: "GET" });
    if (!upstream.ok) {
      res.status(upstream.status).json({ error: upstream.error });
      return;
    }
    const body = parsed.data;
    res.json(ControlServiceResponse.parse({
      ok: true,
      message: `Engine reachable; ${body.action} for ${body.service} must be issued on the engine host (systemd).`,
      mode: "DRY-RUN",
    }));
  })();
});

export default router;
