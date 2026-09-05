import { getAuth } from "@clerk/express";
import type { RequestHandler } from "express";

const failedAttempts = new Map<string, { count: number; resetAt: number }>();
const windowMs = 5 * 60 * 1000;
const maxFailures = 10;

export const requireAuth: RequestHandler = (req, res, next) => {
  const key = req.ip || "unknown";
  const now = Date.now();
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