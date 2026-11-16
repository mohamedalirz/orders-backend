// Meta integration: lets each seller connect their Facebook Pages and Instagram
// Business accounts, receive customer messages and reply from your app.
//
// How it works
//   1. Seller clicks "Connect"      -> POST /api/meta/connect returns the Meta login URL.
//   2. Meta sends the seller back   -> GET  /api/meta/callback (public, protected by a one-time `state`).
//      We swap the code for a long-lived token, read the Pages (and linked Instagram accounts),
//      store each Page token ENCRYPTED, and subscribe the Page to webhooks.
//   3. A customer writes            -> POST /api/meta/webhook (public, protected by the X-Hub-Signature-256 check).
//   4. The seller replies           -> POST /api/meta/threads/:id/reply (logged-in users only).
//   5. Live updates                 -> GET  /api/meta/stream (Server-Sent Events, one-time ticket).
//   6. Meta compliance              -> POST /api/meta/deauthorize and /api/meta/data-deletion (required for App Review).
//
// Two routers are exported because they need different protection:
//   metaPublicRouter  mount BEFORE express.json() and BEFORE requireAuth  (webhook needs the raw body)
//   metaRouter        mount AFTER requireAuth                              (uses req.user)

import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import express from "express";
import { z } from "zod";
import { db } from "./db.js";
import { analyzeMessage } from "./ai.js";
import { badRequest, parseId, rateLimit } from "./util.js";

// --------------------------------------------------
// SETTINGS (read at call time, so tests can change them)
// --------------------------------------------------

const cfg = () => ({
  appId: process.env.META_APP_ID || "",
  appSecret: process.env.META_APP_SECRET || "",
  verifyToken: process.env.META_VERIFY_TOKEN || "",
  redirectUri: process.env.META_REDIRECT_URI || "",
  version: process.env.META_GRAPH_VERSION || "v23.0",
  graphBase: process.env.META_GRAPH_BASE || "https://graph.facebook.com",
  scopes: process.env.META_SCOPES ||
    "pages_show_list,pages_messaging,pages_manage_metadata,pages_read_engagement,instagram_basic,instagram_manage_messages,business_management",
  frontend: (process.env.FRONTEND_ORIGIN || "http://localhost:5173").split(",")[0].trim()
});

const isConfigured = () => {
  const c = cfg();
  return Boolean(c.appId && c.appSecret && c.verifyToken && c.redirectUri && tokenKey());
};

const MESSAGING_WINDOW_MS = 24 * 3600 * 1000;

// --------------------------------------------------
// DATABASE
// --------------------------------------------------

db.exec(`
CREATE TABLE IF NOT EXISTS meta_oauth_states (
  state TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

-- One row per connected Facebook Page or Instagram account.
-- account_id = Page id (facebook) or Instagram business account id (instagram).
CREATE TABLE IF NOT EXISTS meta_connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  platform TEXT NOT NULL CHECK (platform IN ('facebook', 'instagram')),
  account_id TEXT NOT NULL,
  page_id TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  token_enc TEXT NOT NULL,
  fb_user_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (platform, account_id)
);

CREATE TABLE IF NOT EXISTS meta_threads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  connection_id INTEGER NOT NULL REFERENCES meta_connections(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL,
  customer_name TEXT NOT NULL DEFAULT '',
  last_message TEXT NOT NULL DEFAULT '',
  last_message_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_inbound_at INTEGER NOT NULL DEFAULT 0,
  unread INTEGER NOT NULL DEFAULT 0,
  UNIQUE (connection_id, customer_id)
);

CREATE TABLE IF NOT EXISTS meta_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  thread_id INTEGER NOT NULL REFERENCES meta_threads(id) ON DELETE CASCADE,
  mid TEXT NOT NULL,
  direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
  text TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (thread_id, mid)
);

CREATE TABLE IF NOT EXISTS meta_deletions (
  code TEXT PRIMARY KEY,
  fb_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_meta_conn_user ON meta_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_meta_threads_user ON meta_threads(user_id, last_message_at);
CREATE INDEX IF NOT EXISTS idx_meta_msgs_thread ON meta_messages(thread_id, id);
`);

// Databases created by an earlier version of this file: add the new column.
if (!db.prepare("PRAGMA table_info(meta_connections)").all().some(c => c.name === "fb_user_id")) {
  db.exec("ALTER TABLE meta_connections ADD COLUMN fb_user_id TEXT NOT NULL DEFAULT ''");
}
db.exec("CREATE INDEX IF NOT EXISTS idx_meta_conn_fbuser ON meta_connections(fb_user_id)");

db.prepare("DELETE FROM meta_oauth_states WHERE expires_at < ?").run(Date.now());

// --------------------------------------------------
// TOKEN ENCRYPTION (AES-256-GCM). Page tokens give full control of a Page,
// so they are never stored in clear text.
// --------------------------------------------------

function tokenKey() {
  const key = Buffer.from(process.env.META_TOKEN_KEY || "", "base64");
  return key.length === 32 ? key : null;
}

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", tokenKey(), iv);
  const data = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), data].map(b => b.toString("base64")).join(".");
}

function decrypt(stored) {
  const [iv, tag, data] = String(stored).split(".").map(s => Buffer.from(s, "base64"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", tokenKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

// --------------------------------------------------
// GRAPH API HELPER
// --------------------------------------------------

class GraphError extends Error {
  constructor(payload, status) {
    super(payload?.message || `Graph API error (${status})`);
    this.code = payload?.code;
    this.status = status;
  }
}

async function graph(pathname, { method = "GET", token, params = {}, body } = {}) {
  const c = cfg();
  const url = new URL(`${c.graphBase}/${c.version}${pathname}`);

  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));

  if (token) {
    url.searchParams.set("access_token", token);
    // appsecret_proof: proves the call comes from our server, even if a token leaks.
    url.searchParams.set("appsecret_proof", crypto.createHmac("sha256", c.appSecret).update(token).digest("hex"));
  }

  const response = await fetch(url, {
    method,
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(15_000)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.error) throw new GraphError(data.error, response.status);

  return data;
}

// --------------------------------------------------
// CONNECTION HELPERS
// --------------------------------------------------

const publicConnection = row => ({
  id: row.id,
  platform: row.platform,
  account_id: row.account_id,
  name: row.name,
  status: row.status,
  created_at: row.created_at
});

const getConnection = (id, uid) =>
  db.prepare("SELECT * FROM meta_connections WHERE id = ? AND user_id = ?").get(id, uid);

const upsertConnection = db.prepare(`
  INSERT INTO meta_connections (user_id, platform, account_id, page_id, name, token_enc, fb_user_id, status)
  VALUES (@user_id, @platform, @account_id, @page_id, @name, @token_enc, @fb_user_id, 'active')
  ON CONFLICT (platform, account_id) DO UPDATE
    SET page_id = excluded.page_id, name = excluded.name, token_enc = excluded.token_enc,
        fb_user_id = excluded.fb_user_id, status = 'active'
    WHERE meta_connections.user_id = excluded.user_id
`);

function markNeedsReconnect(error, connection) {
  // 190 = token expired or revoked (seller changed password, removed the app...).
  if (error?.code === 190) {
    db.prepare("UPDATE meta_connections SET status = 'needs_reconnect' WHERE page_id = ?").run(connection.page_id);
  }
}

// --------------------------------------------------
// LIVE EVENTS (Server-Sent Events)
// The browser's EventSource cannot send an Authorization header, so the logged-in app first asks for a
// one-time ticket (valid 60 s), then opens GET /api/meta/stream?ticket=...
// --------------------------------------------------

const bus = new EventEmitter();
bus.setMaxListeners(0);

const tickets = new Map(); // ticket -> { uid, exp }
const emit = (uid, event) => bus.emit(`u${uid}`, event);

setInterval(() => {
  const now = Date.now();
  for (const [t, v] of tickets) if (v.exp < now) tickets.delete(t);
}, 60_000).unref();

// --------------------------------------------------
// PUBLIC ROUTER: OAuth callback + webhook (no login token available here)
// --------------------------------------------------

export const metaPublicRouter = express.Router();

metaPublicRouter.get("/callback", async (req, res) => {
  const c = cfg();
  const back = result => res.redirect(`${c.frontend}/settings?meta=${result}`);

  if (!isConfigured()) return back("not_configured");
  if (req.query.error) return back("denied");

  // The state ties this callback to the seller who started it, and works only once.
  const state = String(req.query.state || "");
  const row = state && db.prepare("SELECT * FROM meta_oauth_states WHERE state = ?").get(state);
  if (row) db.prepare("DELETE FROM meta_oauth_states WHERE state = ?").run(state);
  if (!row || row.expires_at < Date.now()) return back("invalid_state");

  const code = String(req.query.code || "");
  if (!code) return back("denied");

  try {
    const short = await graph("/oauth/access_token", {
      params: { client_id: c.appId, client_secret: c.appSecret, redirect_uri: c.redirectUri, code }
    });

    // Page tokens obtained from a long-lived user token do not expire.
    const long = await graph("/oauth/access_token", {
      params: {
        grant_type: "fb_exchange_token",
        client_id: c.appId,
        client_secret: c.appSecret,
        fb_exchange_token: short.access_token
      }
    });

    // Meta's deauthorize / data-deletion callbacks identify the seller by this id.
    const me = await graph("/me", { token: long.access_token, params: { fields: "id" } });

    const pages = await graph("/me/accounts", {
      token: long.access_token,
      params: { fields: "id,name,access_token,instagram_business_account{id,username}", limit: 100 }
    });

    let connected = 0;

    for (const page of pages.data || []) {
      const token_enc = encrypt(page.access_token);
      const base = { user_id: row.user_id, page_id: page.id, token_enc, fb_user_id: String(me.id || "") };

      // Without this call Meta never sends us this Page's messages.
      try {
        await graph(`/${page.id}/subscribed_apps`, {
          method: "POST",
          token: page.access_token,
          params: { subscribed_fields: "messages,messaging_postbacks" }
        });
      } catch (error) {
        console.error(`Meta subscribe failed for page ${page.id}:`, error.message);
        continue;
      }

      connected += upsertConnection.run({ ...base, platform: "facebook", account_id: page.id, name: page.name }).changes;

      const ig = page.instagram_business_account;
      if (ig?.id) {
        connected += upsertConnection.run({
          ...base, platform: "instagram", account_id: ig.id, name: ig.username ? `@${ig.username}` : page.name
        }).changes;
      }
    }

    return back(connected ? "connected" : "no_pages");
  } catch (error) {
    console.error("Meta callback error:", error.message);
    return back("failed");
  }
});

// Meta calls this once, when you press "Verify and save" in the app dashboard.
metaPublicRouter.get("/webhook", (req, res) => {
  const { verifyToken } = cfg();
  const ok = verifyToken
    && req.query["hub.mode"] === "subscribe"
    && req.query["hub.verify_token"] === verifyToken;

  if (!ok) return res.sendStatus(403);
  res.status(200).type("text/plain").send(String(req.query["hub.challenge"] || ""));
});

export function validSignature(rawBody, header, secret) {
  if (!secret || typeof header !== "string" || !header.startsWith("sha256=")) return false;

  const expected = Buffer.from(crypto.createHmac("sha256", secret).update(rawBody).digest("hex"));
  const actual = Buffer.from(header.slice(7));

  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

// The signature is computed on the exact bytes Meta sent, so this route reads the RAW body.
metaPublicRouter.post("/webhook", express.raw({ type: "*/*", limit: "1mb" }), (req, res) => {
  if (!validSignature(req.body, req.get("x-hub-signature-256"), cfg().appSecret)) {
    return res.sendStatus(403);
  }

  let payload;
  try { payload = JSON.parse(req.body.toString("utf8")); } catch { return res.sendStatus(400); }

  // Answer fast: Meta retries (and eventually disables the webhook) if we are slow.
  res.status(200).send("EVENT_RECEIVED");

  try {
    processWebhook(payload);
  } catch (error) {
    console.error("Meta webhook processing error:", error);
  }
});

metaPublicRouter.get("/stream", (req, res) => {
  const ticket = String(req.query.ticket || "");
  const found = tickets.get(ticket);
  tickets.delete(ticket);

  if (!found || found.exp < Date.now()) return res.status(401).json({ error: "Invalid or expired ticket" });

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no" // stops nginx from buffering the stream
  });
  res.write("retry: 3000\n: connected\n\n");

  const send = event => res.write(`data: ${JSON.stringify(event)}\n\n`);
  const channel = `u${found.uid}`;
  bus.on(channel, send);

  const ping = setInterval(() => res.write(": ping\n\n"), 25_000);

  req.on("close", () => {
    clearInterval(ping);
    bus.off(channel, send);
  });
});

// --------------------------------------------------
// META COMPLIANCE CALLBACKS (required for App Review)
// Meta POSTs a form field `signed_request` = base64url(signature).base64url(payload)
// --------------------------------------------------

export function parseSignedRequest(signedRequest, secret) {
  const [sig, payload] = String(signedRequest || "").split(".");
  if (!sig || !payload || !secret) return null;

  const expected = crypto.createHmac("sha256", secret).update(payload).digest();
  const actual = Buffer.from(sig, "base64url");

  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return null;

  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return data?.user_id ? { ...data, user_id: String(data.user_id) } : null;
  } catch {
    return null;
  }
}

const formBody = express.urlencoded({ extended: false, limit: "100kb" });

// The seller removed the app inside Facebook: we can no longer use their tokens.
metaPublicRouter.post("/deauthorize", formBody, (req, res) => {
  const data = parseSignedRequest(req.body?.signed_request, cfg().appSecret);
  if (!data) return res.sendStatus(400);

  const users = db.prepare("SELECT DISTINCT user_id FROM meta_connections WHERE fb_user_id = ?").all(data.user_id);

  db.prepare("UPDATE meta_connections SET status = 'needs_reconnect' WHERE fb_user_id = ?").run(data.user_id);
  for (const u of users) emit(u.user_id, { type: "connections_changed" });

  res.sendStatus(200);
});

// The seller asked Facebook to delete their data: we delete everything we hold for that Facebook user.
metaPublicRouter.post("/data-deletion", formBody, (req, res) => {
  const data = parseSignedRequest(req.body?.signed_request, cfg().appSecret);
  if (!data) return res.sendStatus(400);

  const users = db.prepare("SELECT DISTINCT user_id FROM meta_connections WHERE fb_user_id = ?").all(data.user_id);

  // Tokens, conversations and messages go away (ON DELETE CASCADE).
  db.prepare("DELETE FROM meta_connections WHERE fb_user_id = ?").run(data.user_id);
  for (const u of users) emit(u.user_id, { type: "connections_changed" });

  const code = crypto.randomBytes(12).toString("hex");
  db.prepare("INSERT INTO meta_deletions (code, fb_user_id) VALUES (?, ?)").run(code, data.user_id);

  const origin = (() => { try { return new URL(cfg().redirectUri).origin; } catch { return ""; } })();

  // Meta wants exactly this JSON shape back.
  res.json({ url: `${origin}/api/meta/deletion-status?code=${code}`, confirmation_code: code });
});

metaPublicRouter.get("/deletion-status", (req, res) => {
  const row = db.prepare("SELECT created_at FROM meta_deletions WHERE code = ?").get(String(req.query.code || ""));

  res.type("html").status(row ? 200 : 404).send(
    row
      ? `<!doctype html><meta charset="utf-8"><title>Data deleted</title><p>Your data was deleted on ${row.created_at} UTC.</p>`
      : `<!doctype html><meta charset="utf-8"><title>Not found</title><p>Unknown confirmation code.</p>`
  );
});

// --------------------------------------------------
// INCOMING MESSAGES
// --------------------------------------------------

const upsertThread = db.prepare(`
  INSERT INTO meta_threads (user_id, connection_id, customer_id) VALUES (?, ?, ?)
  ON CONFLICT (connection_id, customer_id) DO NOTHING
`);

const insertMessage = db.prepare(
  "INSERT OR IGNORE INTO meta_messages (thread_id, mid, direction, text, created_at) VALUES (?, ?, ?, ?, ?)"
);

const storeMessage = db.transaction((connection, customerId, mid, direction, text, timestamp) => {
  upsertThread.run(connection.user_id, connection.id, customerId);

  const thread = db.prepare("SELECT * FROM meta_threads WHERE connection_id = ? AND customer_id = ?")
    .get(connection.id, customerId);

  const stored = insertMessage.run(thread.id, mid, direction, text, new Date(timestamp).toISOString());

  // changes = 0 means Meta sent the same message twice (it retries): ignore it.
  if (!stored.changes) return null;

  if (direction === "in") {
    db.prepare(`
      UPDATE meta_threads
      SET last_message = ?, last_message_at = ?, last_inbound_at = ?, unread = unread + 1
      WHERE id = ?
    `).run(text.slice(0, 200), new Date(timestamp).toISOString(), timestamp, thread.id);
  } else {
    db.prepare("UPDATE meta_threads SET last_message = ?, last_message_at = ? WHERE id = ?")
      .run(text.slice(0, 200), new Date(timestamp).toISOString(), thread.id);
  }

  return thread;
});

export function processWebhook(payload) {
  const platform = payload?.object === "instagram" ? "instagram" : payload?.object === "page" ? "facebook" : null;
  if (!platform) return;

  for (const entry of payload.entry || []) {
    const connection = db.prepare(
      "SELECT * FROM meta_connections WHERE platform = ? AND account_id = ? AND status != 'removed'"
    ).get(platform, String(entry.id));

    if (!connection) continue;

    for (const event of entry.messaging || []) {
      // A tap on a button / quick reply arrives as a "postback" (no `message`): treat its title as text.
      const message = event.message || (event.postback?.mid
        ? { mid: event.postback.mid, text: event.postback.title || event.postback.payload || "" }
        : null);
      if (!message?.mid) continue;

      // "echo" = a message sent BY the page (from our app or from the phone app).
      const isEcho = Boolean(message.is_echo);
      const customerId = String(isEcho ? event.recipient?.id : event.sender?.id || "");
      if (!customerId || customerId === "undefined") continue;

      const text = message.text
        || (message.attachments?.length ? `[${message.attachments[0].type || "attachment"}]` : "");
      if (!text) continue;

      const thread = storeMessage(
        connection, customerId, message.mid, isEcho ? "out" : "in", text, Number(event.timestamp) || Date.now()
      );

      if (thread) {
        emit(connection.user_id, { type: "message", thread_id: thread.id, direction: isEcho ? "out" : "in" });
        if (!thread.customer_name) fetchCustomerName(connection, thread).catch(() => {});
      }
    }
  }
}

async function fetchCustomerName(connection, thread) {
  const fields = connection.platform === "instagram" ? "name,username" : "name";
  const profile = await graph(`/${thread.customer_id}`, { token: decrypt(connection.token_enc), params: { fields } });
  const name = profile.name || (profile.username ? `@${profile.username}` : "");

  if (name) {
    db.prepare("UPDATE meta_threads SET customer_name = ? WHERE id = ?").run(name, thread.id);
    emit(connection.user_id, { type: "thread_updated", thread_id: thread.id });
  }
}

// --------------------------------------------------
// AUTHENTICATED ROUTER (mounted after requireAuth)
// --------------------------------------------------

export const metaRouter = express.Router();

const replyLimiter = rateLimit({ windowMs: 60_000, max: 30, keyFn: req => `meta${req.user.id}` });

metaRouter.get("/status", (req, res) => {
  const rows = db.prepare("SELECT * FROM meta_connections WHERE user_id = ? ORDER BY id").all(req.user.id);
  res.json({ configured: isConfigured(), connections: rows.map(publicConnection) });
});

metaRouter.post("/connect", (req, res) => {
  if (!isConfigured()) return res.status(503).json({ error: "Meta is not configured on this server." });

  const c = cfg();
  const state = crypto.randomBytes(24).toString("base64url");

  db.prepare("INSERT INTO meta_oauth_states (state, user_id, expires_at) VALUES (?, ?, ?)")
    .run(state, req.user.id, Date.now() + 10 * 60_000);

  const url = new URL(`https://www.facebook.com/${c.version}/dialog/oauth`);
  url.searchParams.set("client_id", c.appId);
  url.searchParams.set("redirect_uri", c.redirectUri);
  url.searchParams.set("state", state);
  url.searchParams.set("scope", c.scopes);
  url.searchParams.set("response_type", "code");

  res.json({ url: url.toString() });
});

metaRouter.post("/stream-ticket", rateLimit({ windowMs: 60_000, max: 20, keyFn: req => `metast${req.user.id}` }), (req, res) => {
  const ticket = crypto.randomBytes(24).toString("base64url");
  tickets.set(ticket, { uid: req.user.id, exp: Date.now() + 60_000 });
  res.json({ ticket, url: `/api/meta/stream?ticket=${ticket}` });
});

metaRouter.delete("/connections/:id", async (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid ID" });

  const connection = getConnection(id, req.user.id);
  if (!connection) return res.status(404).json({ error: "Connection not found" });

  db.prepare("DELETE FROM meta_connections WHERE id = ?").run(id);

  // Stop webhooks for this Page once no connection (Facebook or Instagram) uses it any more.
  const stillUsed = db.prepare("SELECT 1 FROM meta_connections WHERE page_id = ?").get(connection.page_id);

  if (!stillUsed) {
    try {
      await graph(`/${connection.page_id}/subscribed_apps`, { method: "DELETE", token: decrypt(connection.token_enc) });
    } catch (error) {
      console.error("Meta unsubscribe failed:", error.message);
    }
  }

  res.json({ ok: true });
});

metaRouter.get("/threads", (req, res) => {
  const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));
  const connectionId = parseId(req.query.connection_id);

  const rows = db.prepare(`
    SELECT t.id, t.connection_id, c.platform, c.name AS account_name, t.customer_id, t.customer_name,
           t.last_message, t.last_message_at, t.last_inbound_at, t.unread
    FROM meta_threads t JOIN meta_connections c ON c.id = t.connection_id
    WHERE t.user_id = ? ${connectionId ? "AND t.connection_id = ?" : ""}
    ORDER BY t.last_message_at DESC LIMIT ?
  `).all(...[req.user.id, ...(connectionId ? [connectionId] : []), limit]);

  res.json(rows.map(r => ({
    ...r,
    can_reply: Date.now() - r.last_inbound_at < MESSAGING_WINDOW_MS
  })));
});

function getThread(req) {
  const id = parseId(req.params.id);
  if (!id) return null;
  return db.prepare("SELECT * FROM meta_threads WHERE id = ? AND user_id = ?").get(id, req.user.id) || null;
}

metaRouter.get("/threads/:id/messages", (req, res) => {
  const thread = getThread(req);
  if (!thread) return res.status(404).json({ error: "Conversation not found" });

  db.prepare("UPDATE meta_threads SET unread = 0 WHERE id = ?").run(thread.id);

  // ?before=<message id> loads older messages; ?limit=1..200 (default 50).
  const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));
  const before = parseId(req.query.before);

  const rows = db.prepare(
    `SELECT id, direction, text, created_at FROM meta_messages
     WHERE thread_id = ? ${before ? "AND id < ?" : ""} ORDER BY id DESC LIMIT ?`
  ).all(...[thread.id, ...(before ? [before] : []), limit + 1]);

  const messages = rows.slice(0, limit).reverse();

  res.json({
    has_more: rows.length > limit,
    thread: {
      id: thread.id,
      customer_name: thread.customer_name,
      can_reply: Date.now() - thread.last_inbound_at < MESSAGING_WINDOW_MS
    },
    messages
  });
});

const replySchema = z.object({ text: z.string().trim().min(1, "Message is empty").max(1000) });

metaRouter.post("/threads/:id/reply", replyLimiter, async (req, res) => {
  const thread = getThread(req);
  if (!thread) return res.status(404).json({ error: "Conversation not found" });

  const parsed = replySchema.safeParse(req.body || {});
  if (!parsed.success) return badRequest(res, parsed.error, "Invalid message");

  // Meta only allows free replies within 24 hours of the customer's last message.
  if (Date.now() - thread.last_inbound_at >= MESSAGING_WINDOW_MS) {
    return res.status(409).json({
      error: "More than 24 hours since the customer's last message: Meta no longer allows a reply here."
    });
  }

  const connection = getConnection(thread.connection_id, req.user.id);
  if (!connection) return res.status(404).json({ error: "Connection not found" });
  if (connection.status !== "active") {
    return res.status(409).json({ error: "This account must be reconnected before you can reply." });
  }

  try {
    const sent = await graph(`/${connection.page_id}/messages`, {
      method: "POST",
      token: decrypt(connection.token_enc),
      body: {
        recipient: { id: thread.customer_id },
        messaging_type: "RESPONSE",
        message: { text: parsed.data.text }
      }
    });

    // Saved with Meta's message id, so the "echo" webhook that follows is recognised as a duplicate.
    storeMessage(connection, thread.customer_id, sent.message_id, "out", parsed.data.text, Date.now());
    emit(req.user.id, { type: "message", thread_id: thread.id, direction: "out" });

    return res.status(201).json({ ok: true, message_id: sent.message_id });
  } catch (error) {
    markNeedsReconnect(error, connection);
    console.error("Meta send error:", error.message);
    return res.status(502).json({ error: `Meta refused the message: ${error.message}` });
  }
});

// Reuses your Groq pipeline: customer messages in -> suggested reply + order draft out.
metaRouter.post("/threads/:id/suggest", rateLimit({ windowMs: 60_000, max: 20, keyFn: req => `metaai${req.user.id}` }),
  async (req, res) => {
    const thread = getThread(req);
    if (!thread) return res.status(404).json({ error: "Conversation not found" });

    const inbound = db.prepare(
      "SELECT text FROM meta_messages WHERE thread_id = ? AND direction = 'in' ORDER BY id DESC LIMIT 5"
    ).all(thread.id).reverse().map(m => m.text);

    if (!inbound.length) return res.status(400).json({ error: "No customer message to analyse yet." });

    try {
      const products = db.prepare("SELECT id, name, price, aliases FROM products WHERE user_id = ? ORDER BY name")
        .all(req.user.id);
      const result = await analyzeMessage(inbound.join("\n").slice(-2000), { products });

      res.json({
        suggested_reply: result.suggested_reply || "",
        extracted: result.extracted,
        items: result.items,
        missing: result.missing,
        customer_intent: result.customer_intent
      });
    } catch (error) {
      console.error("Meta suggest error:", error.message);
      res.status(502).json({ error: "AI analysis failed. Try again in a moment." });
    }
  });

metaRouter.delete("/threads/:id", (req, res) => {
  const thread = getThread(req);
  if (!thread) return res.status(404).json({ error: "Conversation not found" });

  db.prepare("DELETE FROM meta_threads WHERE id = ?").run(thread.id);
  res.json({ ok: true });
});
