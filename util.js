// Small helpers shared by server.js and auth.js.

// In-memory rate limiter. keyFn decides who is counted (default: the caller's IP).
export function rateLimit({ windowMs, max, keyFn = req => req.ip, message = "Too many requests. Please slow down." }) {
  const hits = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [key, times] of hits) {
      if (!times.some(t => now - t < windowMs)) hits.delete(key);
    }
  }, 60_000).unref();

  return (req, res, next) => {
    const key = keyFn(req);
    const now = Date.now();
    const recent = (hits.get(key) || []).filter(t => now - t < windowMs);

    if (recent.length >= max) {
      res.set("Retry-After", String(Math.ceil(windowMs / 1000)));
      return res.status(429).json({ error: message });
    }

    recent.push(now);
    hits.set(key, recent);
    next();
  };
}

export function firstIssue(error) {
  const issue = error.issues?.[0];
  if (!issue) return "Invalid data";
  const where = issue.path?.length ? `${issue.path.join(".")}: ` : "";
  return `${where}${issue.message}`;
}

export function badRequest(res, error, fallback = "Invalid data") {
  return res.status(400).json({
    error: error.issues ? firstIssue(error) : fallback,
    details: (error.issues || []).map(i => ({ path: i.path.join("."), message: i.message }))
  });
}

export function parseId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}
