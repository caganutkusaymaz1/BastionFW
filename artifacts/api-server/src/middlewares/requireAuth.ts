import { getAuth } from "@clerk/express";
import type { RequestHandler } from "express";

const failedAttempts = new Map<string, { count: number; resetAt: number }>();
const windowMs = 5 * 60 * 1000;
const maxFailures = 10;
// Unauthenticated probes must not grow the tracker without bound: without a
// periodic sweep a spoofed-source flood can exhaust process memory (DoS).
const cleanupIntervalMs = 5 * 60 * 1000;
const maxTrackedIps = 10_000;

let lastCleanup = Date.now();

function sweepStaleEntries(now: number) {
  if (now - lastCleanup < cleanupIntervalMs) return;
  lastCleanup = now;
  for (const [key, entry] of failedAttempts) {
    if (entry.resetAt <= now) failedAttempts.delete(key);
  }
  // Absolute bound: if a flood still overflows the map, drop the oldest
  // window rather than growing without limit.
  if (failedAttempts.size > maxTrackedIps) {
    const overflow = failedAttempts.size - maxTrackedIps;
    let dropped = 0;
    for (const key of failedAttempts.keys()) {
      if (dropped >= overflow) break;
      failedAttempts.delete(key);
      dropped += 1;
    }
  }
}

export const requireAuth: RequestHandler = (req, res, next) => {
  const key = req.ip || "unknown";
  const now = Date.now();
  sweepStaleEntries(now);

  const record = failedAttempts.get(key);
  if (record && record.resetAt > now && record.count >= maxFailures) {
    res.status(429).json({ error: "Too many authentication attempts. Try again later." });
    return;
  }

  const auth = getAuth(req);
  const userId = auth?.sessionClaims?.userId || auth?.userId;

  if (!userId) {
    const nextRecord = record && record.resetAt > now
      ? { count: record.count + 1, resetAt: record.resetAt }
      : { count: 1, resetAt: now + windowMs };
    failedAttempts.set(key, nextRecord);
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  failedAttempts.delete(key);
  next();
};
