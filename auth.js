// Accounts and logins.
//
// - Passwords are never stored: only a salted scrypt hash (built into Node).
// - A login creates a random token. The browser keeps the token; the database keeps only
//   its SHA-256 hash and an expiry date. Logout deletes the row, so a stolen token stops working.
// - The first account on a new server is always allowed and takes over any orders/products
//   that already exist (data saved before accounts existed). After that, sign-ups are closed
//   unless ALLOW_SIGNUP=1 is set in .env.

import crypto from "node:crypto";
import { promisify } from "node:util";
import express from "express";
import { z } from "zod";
import { db } from "./db.js";
import { badRequest, rateLimit } from "./util.js";

const scrypt = promisify(crypto.scrypt);

const SESSION_MS = 30 * 24 * 3600 * 1000;
const FAIL_WINDOW_MS = 15 * 60_000;
const MAX_FAILS_PER_ACCOUNT = 5;
const MAX_FAILS_PER_IP = 20;

const sha256 = value => crypto.createHash("sha256").update(String(value)).digest("hex");

// --------------------------------------------------
// PASSWORDS
// --------------------------------------------------

const SCRYPT = { N: 16384, r: 8, p: 1 };

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, 64, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("hex")}$${key.toString("hex")}`;
}

export async function verifyPassword(password, stored) {
  const [kind, N, r, p, saltHex, keyHex] = String(stored).split("$");
  if (kind !== "scrypt" || !keyHex) return false;

  const expected = Buffer.from(keyHex, "hex");
  const actual = await scrypt(password, Buffer.from(saltHex, "hex"), expected.length, {
    N: Number(N), r: Number(r), p: Number(p)
  });

  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

// Used when the email does not exist, so a wrong email and a wrong password take the same time.
let dummyHash;
const getDummyHash = async () => (dummyHash ??= await hashPassword("not-a-real-password"));

// --------------------------------------------------
// VALIDATION
// --------------------------------------------------

const email = z.string().trim().toLowerCase().email("Enter a valid email address").max(120);
const name = z.string().trim().min(1, "Your name is required").max(80);
const storeName = z.string().trim().min(1, "Store name is required").max(80);
const newPassword = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(200, "Password is too long");

const registerSchema = z.object({ name, store_name: storeName, email, password: newPassword });
const loginSchema = z.object({ email, password: z.string().min(1, "Password is required").max(200) });
const profileSchema = z.object({ name: name.optional(), store_name: storeName.optional() });
const passwordSchema = z.object({
  current_password: z.string().min(1, "Current password is required").max(200),
  new_password: newPassword
});

const publicUser = user => ({
  id: user.id,
  email: user.email,
  name: user.name,
  store_name: user.store_name
});

// --------------------------------------------------
// SESSIONS
// --------------------------------------------------

function createSession(userId, req) {
  const token = crypto.randomBytes(32).toString("base64url");

  db.prepare("INSERT INTO sessions (user_id, token_hash, expires_at, user_agent) VALUES (?, ?, ?, ?)")
    .run(userId, sha256(token), Date.now() + SESSION_MS, String(req.get("user-agent") || "").slice(0, 200));

  return token;
}

const tokenFrom = req => {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7).trim() : "";
};

// Put this in front of every route that needs a logged-in user. It sets req.user and req.sessionId.
export function requireAuth(req, res, next) {
  const token = tokenFrom(req);

  const row = token && db.prepare(`
    SELECT s.id AS session_id, u.id, u.email, u.name, u.store_name
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).get(sha256(token), Date.now());

  if (!row) return res.status(401).json({ error: "Please sign in" });

  req.user = publicUser(row);
  req.sessionId = row.session_id;
  next();
}

// Expired sessions are removed once an hour.
setInterval(() => db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(Date.now()), 3600_000).unref();

// --------------------------------------------------
// FAILED-LOGIN COUNTER (in memory)
// --------------------------------------------------

const failures = new Map(); // key -> { count, first }

function failCount(key) {
  const record = failures.get(key);
  if (!record) return 0;

  if (Date.now() - record.first > FAIL_WINDOW_MS) {
    failures.delete(key);
    return 0;
  }

  return record.count;
}

function addFailure(key) {
  const record = failures.get(key);

  if (record && Date.now() - record.first <= FAIL_WINDOW_MS) record.count += 1;
  else failures.set(key, { count: 1, first: Date.now() });
}

// --------------------------------------------------
// ROUTES  (mounted at /api/auth)
// --------------------------------------------------

export const authRouter = express.Router();

const hasUsers = () => db.prepare("SELECT 1 FROM users LIMIT 1").get() !== undefined;
const signupOpen = () => process.env.ALLOW_SIGNUP === "1";

// The login page asks this to know which form to show.
authRouter.get("/status", (_, res) => {
  const users = hasUsers();
  res.json({ hasUsers: users, signupOpen: !users || signupOpen() });
});

authRouter.post(
  "/register",
  rateLimit({ windowMs: 3600_000, max: 10, message: "Too many sign-ups from this address. Try later." }),
  async (req, res) => {
    const parsed = registerSchema.safeParse(req.body || {});
    if (!parsed.success) return badRequest(res, parsed.error);

    if (hasUsers() && !signupOpen()) {
      return res.status(403).json({ error: "Sign-ups are closed on this server." });
    }

    const data = parsed.data;
    const passwordHash = await hashPassword(data.password);

    try {
      const userId = db.transaction(() => {
        // Checked again inside the transaction, in case two sign-ups arrive together.
        const first = !hasUsers();
        if (!first && !signupOpen()) throw Object.assign(new Error("closed"), { code: "CLOSED" });

        const result = db
          .prepare("INSERT INTO users (email, name, store_name, password_hash) VALUES (?, ?, ?, ?)")
          .run(data.email, data.name, data.store_name, passwordHash);

        const id = Number(result.lastInsertRowid);

        // The first account takes over everything saved before accounts existed.
        if (first) {
          db.prepare("UPDATE orders SET user_id = ? WHERE user_id IS NULL").run(id);
          db.prepare("UPDATE products SET user_id = ? WHERE user_id IS NULL").run(id);
        }

        return id;
      })();

      const user = db.prepare("SELECT id, email, name, store_name FROM users WHERE id = ?").get(userId);

      res.status(201).json({ token: createSession(userId, req), user: publicUser(user) });
    } catch (error) {
      if (error.code === "CLOSED") return res.status(403).json({ error: "Sign-ups are closed on this server." });
      if (String(error.code).startsWith("SQLITE_CONSTRAINT")) {
        return res.status(409).json({ error: "An account with this email already exists." });
      }
      throw error;
    }
  }
);

authRouter.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body || {});
  if (!parsed.success) return badRequest(res, parsed.error);

  const { email: address, password } = parsed.data;
  const accountKey = `acct|${req.ip}|${address}`;
  const ipKey = `ip|${req.ip}`;

  if (failCount(accountKey) >= MAX_FAILS_PER_ACCOUNT || failCount(ipKey) >= MAX_FAILS_PER_IP) {
    return res.status(429).json({ error: "Too many failed attempts. Try again in 15 minutes." });
  }

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(address);
  const ok = await verifyPassword(password, user ? user.password_hash : await getDummyHash());

  if (!user || !ok) {
    addFailure(accountKey);
    addFailure(ipKey);
    return res.status(401).json({ error: "Wrong email or password" });
  }

  failures.delete(accountKey);

  res.json({ token: createSession(user.id, req), user: publicUser(user) });
});

authRouter.post("/logout", requireAuth, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE id = ?").run(req.sessionId);
  res.json({ ok: true });
});

authRouter.get("/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

authRouter.patch("/me", requireAuth, (req, res) => {
  const parsed = profileSchema.safeParse(req.body || {});
  if (!parsed.success) return badRequest(res, parsed.error);

  const { name: newName, store_name: newStore } = parsed.data;

  db.prepare("UPDATE users SET name = COALESCE(?, name), store_name = COALESCE(?, store_name) WHERE id = ?")
    .run(newName ?? null, newStore ?? null, req.user.id);

  res.json({ user: publicUser(db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id)) });
});

authRouter.post("/password", requireAuth, async (req, res) => {
  const parsed = passwordSchema.safeParse(req.body || {});
  if (!parsed.success) return badRequest(res, parsed.error);

  const key = `pw|${req.user.id}`;

  if (failCount(key) >= MAX_FAILS_PER_ACCOUNT) {
    return res.status(429).json({ error: "Too many attempts. Try again in 15 minutes." });
  }

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);

  if (!(await verifyPassword(parsed.data.current_password, user.password_hash))) {
    addFailure(key);
    return res.status(400).json({ error: "Current password is wrong" });
  }

  const hash = await hashPassword(parsed.data.new_password);

  db.transaction(() => {
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, user.id);
    // Every other device must sign in again with the new password.
    db.prepare("DELETE FROM sessions WHERE user_id = ? AND id != ?").run(user.id, req.sessionId);
  })();

  failures.delete(key);
  res.json({ ok: true });
});

// Sign out everywhere else (lost phone, shared computer).
authRouter.post("/logout-others", requireAuth, (req, res) => {
  const result = db.prepare("DELETE FROM sessions WHERE user_id = ? AND id != ?").run(req.user.id, req.sessionId);
  res.json({ ok: true, signed_out: result.changes });
});
