import { Router, type IRouter, type Response } from "express";
import { isIP } from "node:net";
import {
  BanAddressBody,
  BanAddressResponse,
  GetSecurityOverviewResponse,
  ListSecurityEventsQueryParams,
  ListSecurityEventsResponse,
  UnbanAddressBody,
  UnbanAddressResponse,
} from "@workspace/api-zod";
import { requireAuth } from "../middlewares/requireAuth";
import { logger } from "../lib/logger";
import {
  BastionUnavailableError,
  attackCountsFrom,
  eventIdFor,
  fetchStatus,
  liveEventsPerMinute,
  postBanAction,
  snapshotThreatIntel,
  type BastionSnapshot,
  type SnapshotAlert,
} from "../lib/bastionfw";

const router: IRouter = Router();

router.use(requireAuth);

function respondProxyError(res: Response, err: unknown, context: string): void {
  if (err instanceof BastionUnavailableError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  logger.warn({ err, context }, "Failed to serve live BastionFW data");
  res.status(502).json({
    error: `The BastionFW dashboard returned data that could not be mapped (${context}).`,
  });
}

function eventStatus(snapshot: BastionSnapshot, alert: SnapshotAlert): "blocked" | "observed" | "mitigated" {
  if (alert.ip && snapshot.blocked_addresses.includes(alert.ip)) {
    return "blocked";
  }
  if (alert.severity === "critical") {
    return "mitigated";
  }
  return "observed";
}

router.get("/overview", async (_req, res) => {
  try {
    const snapshot = await fetchStatus();
    const overview = GetSecurityOverviewResponse.parse({
      ready: snapshot.ready,
      mode: snapshot.mode,
      uptimeSeconds: snapshot.uptime_seconds,
      queueDepth: snapshot.queue_depth,
      logsProcessed: snapshot.logs_processed,
      threatsDetected: snapshot.threats_detected,
      ipsBlocked: snapshot.ips_blocked,
      pipelineErrors: snapshot.pipeline_errors,
      eventsPerMinute: liveEventsPerMinute(snapshot),
      protectedSources: snapshot.sources.length,
      attackCounts: attackCountsFrom(snapshot),
      // Time-series history is not produced by the engine; an empty, real
      // series beats fabricated chart points.
      traffic: [],
      blockedAddresses: snapshot.blocked_addresses,
      threatIntel: snapshotThreatIntel(snapshot),
      services: snapshot.services,
    });
    res.json(overview);
  } catch (err) {
    respondProxyError(res, err, "overview");
  }
});

router.get("/events", async (req, res) => {
  try {
    const parsed = ListSecurityEventsQueryParams.safeParse({
      limit: req.query.limit,
      severity: req.query.severity,
    });
    if (!parsed.success) {
      res.status(400).json({ error: "Invalid event query." });
      return;
    }
    const { limit, severity } = parsed.data;
    const snapshot = await fetchStatus();
    const alerts = snapshot.alerts
      .filter((alert) => !severity || alert.severity === severity)
      .slice(0, limit);
    const events = alerts.map((alert, index) => ({
      id: eventIdFor(alert, index),
      timestamp: new Date(alert.timestamp * 1000).toISOString(),
      severity: alert.severity,
      rule: alert.rule,
      source: alert.source,
      ip: alert.ip ?? "",
      evidence: alert.evidence,
      status: eventStatus(snapshot, alert),
    }));
    res.json(ListSecurityEventsResponse.parse(events));
  } catch (err) {
    respondProxyError(res, err, "events");
  }
});

router.post("/actions/ban", async (req, res) => {
  const parsed = BanAddressBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "A valid IP address is required." });
    return;
  }
  const ip = parsed.data.ip.trim();
  if (!isPublicAddress(ip)) {
    res.status(400).json({ error: "Only public IP addresses can be blocked." });
    return;
  }
  try {
    const result = await postBanAction("ban", ip);
    res.json(BanAddressResponse.parse(result));
  } catch (err) {
    respondProxyError(res, err, "ban");
  }
});

router.post("/actions/unban", async (req, res) => {
  const parsed = UnbanAddressBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "A valid IP address is required." });
    return;
  }
  const ip = parsed.data.ip.trim();
  if (!isPublicAddress(ip)) {
    res.status(400).json({ error: "Only public IP addresses can be unblocked." });
    return;
  }
  try {
    const result = await postBanAction("unban", ip);
    res.json(UnbanAddressResponse.parse(result));
  } catch (err) {
    respondProxyError(res, err, "unban");
  }
});

async function respondNotImplemented(res: Response, message: string): Promise<void> {
  try {
    const snapshot = await fetchStatus();
    res.status(501).json({
      ok: false,
      message,
      mode: snapshot.mode,
    });
  } catch (err) {
    respondProxyError(res, err, "unsupported action");
  }
}

router.post("/actions/threat-intel", async (_req, res) => {
  // No runtime threat-intel control exists in the Python engine; report the
  // live mode truthfully instead of pretending a refresh was staged.
  await respondNotImplemented(
    res,
    "Threat intelligence refresh is not implemented by the BastionFW engine.",
  );
});

router.post("/actions/service", async (req, res) => {
  const service = (req.body as { service?: string } | undefined)?.service ?? "unknown";
  await respondNotImplemented(
    res,
    `Service control for "${service}" is not implemented by the BastionFW engine.`,
  );
});

function isPublicAddress(value: string) {
  if (isIP(value) === 6) {
    const normalized = value.toLowerCase();
    return normalized !== "::1" &&
      normalized !== "::" &&
      !normalized.startsWith("fc") &&
      !normalized.startsWith("fd") &&
      !normalized.startsWith("fe8") &&
      !normalized.startsWith("fe9") &&
      !normalized.startsWith("fea") &&
      !normalized.startsWith("feb") &&
      !normalized.startsWith("ff");
  }
  if (isIP(value) !== 4) return false;
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part))) return false;
  const numbers = parts.map(Number);
  if (numbers.some((part) => part < 0 || part > 255)) return false;
  const [a, b] = numbers;
  return !(a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a >= 224));
}

export default router;
