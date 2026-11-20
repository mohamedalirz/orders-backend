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

// Automatic order detection: where each conversation stands.
//   auto_status  '' | 'order_created' | 'needs_review' | 'not_order'
//   order_cutoff last customer message already used for an order (the next order starts after it)
{
  const have = db.prepare("PRAGMA table_info(meta_threads)").all().map(c => c.name);
  for (const [name, definition] of [
    ["auto_status", "TEXT NOT NULL DEFAULT ''"],
    ["auto_note", "TEXT NOT NULL DEFAULT ''"],
    ["order_id", "INTEGER"],
    ["order_cutoff", "INTEGER NOT NULL DEFAULT 0"],
    ["last_auto_reply", "TEXT NOT NULL DEFAULT ''"],
    ["draft_items", "TEXT NOT NULL DEFAULT ''"],   // what the automation last wrote into the open order's items
    ["last_result", "TEXT NOT NULL DEFAULT ''"],   // the AI's last reading of this conversation (shown without clicking)
    ["analyzed_upto", "INTEGER NOT NULL DEFAULT 0"] // last customer message already analysed
  ]) {
    if (!have.includes(name)) db.exec(`ALTER TABLE meta_threads ADD COLUMN ${name} ${definition}`);
  }
}

// An order built from a conversation remembers WHICH conversation it belongs to, and whether it is still
// a draft waiting for the customer. The automation only ever edits orders with draft = 1 that carry
// the id of the conversation it is working on.
{
  const have = db.prepare("PRAGMA table_info(orders)").all().map(c => c.name);
  if (!have.includes("meta_thread_id")) db.exec("ALTER TABLE orders ADD COLUMN meta_thread_id INTEGER");
  if (!have.includes("draft")) db.exec("ALTER TABLE orders ADD COLUMN draft INTEGER NOT NULL DEFAULT 0");
  db.exec("CREATE INDEX IF NOT EXISTS idx_orders_meta_thread ON orders(meta_thread_id)");
}

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

  console.log(`Meta webhook verification request: ${ok ? "OK" : "REJECTED (verify token mismatch)"}`);

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
  const signatureOk = validSignature(req.body, req.get("x-hub-signature-256"), cfg().appSecret);
  console.log(`Meta webhook POST received. Signature ${signatureOk ? "valid" : "INVALID"}, ${req.body?.length || 0} bytes`);

  if (!signatureOk) {
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

// Sends a text to a customer through the Page / Instagram account and stores it as an outgoing message.
async function sendText(connection, thread, text) {
  const sent = await graph(`/${connection.page_id}/messages`, {
    method: "POST",
    token: decrypt(connection.token_enc),
    body: {
      recipient: { id: thread.customer_id },
      messaging_type: "RESPONSE",
      message: { text }
    }
  });

  // Saved with Meta's message id, so the "echo" webhook that follows is recognised as a duplicate.
  storeMessage(connection, thread.customer_id, sent.message_id, "out", text, Date.now());
  emit(connection.user_id, { type: "message", thread_id: thread.id, direction: "out" });

  return sent;
}

// --------------------------------------------------
// AUTOMATIC ORDERS
// Every customer message is analysed with the same AI extraction as the AI Inbox (after a short quiet time,
// so a burst of messages counts once) and the customer is answered.
//
//   * An order is saved as soon as a product is detected, even if the customer has not given everything yet
//     (a DRAFT). The customer is asked for what is missing.
//   * When the customer sends more, the SAME draft is completed. It is found through the conversation that
//     owns it (orders.meta_thread_id + orders.draft = 1), never by guessing, so no other order can be touched.
//   * Existing values are never overwritten: only empty fields are filled (so a correction made by the seller
//     is kept). Items are replaced only while they are still exactly what the automation wrote.
//   * A complete draft becomes a normal order; the next order request starts a new order.
//
// server.js supplies the database side (same validation as manual orders) through setAutoOrderHandler.
//
//   META_AUTO_ORDERS=0            turns all of this off
//   META_AUTO_DELAY_MS            quiet time before analysing (default 5000)
//   META_AUTO_MIN_CONFIDENCE      below this a draft is not completed automatically (default 0.6)
//   META_AUTO_REPLY=0             saves orders but does not answer customers
//   META_AUTO_REPLY_CHAT=0        does not answer questions (only confirms orders / asks for missing details)
//   META_AUTO_REQUIRE_ADDRESS=1   also requires a street address before an order is complete
// --------------------------------------------------

let autoOrderHandler = null;
export const setAutoOrderHandler = fn => { autoOrderHandler = fn; };

const autoTimers = new Map();   // thread id -> timer
const autoRunning = new Set();  // conversations being analysed right now

function scheduleAutoOrder(threadId) {
  if (!autoOrderHandler || process.env.META_AUTO_ORDERS === "0") return;

  clearTimeout(autoTimers.get(threadId));

  const delay = Number(process.env.META_AUTO_DELAY_MS ?? 5_000);

  const run = () => {
    autoTimers.delete(threadId);

    // A new message arrived while the AI was still working on this conversation: wait for it to finish.
    if (autoRunning.has(threadId)) {
      autoTimers.set(threadId, setTimeout(run, Math.min(2000, delay)));
      return;
    }

    autoRunning.add(threadId);
    autoProcessThread(threadId)
      .catch(error => console.error("Auto order error:", error.message))
      .finally(() => autoRunning.delete(threadId));
  };

  autoTimers.set(threadId, setTimeout(run, delay));
}

const SOURCE_NAME = { facebook: "Facebook", instagram: "Instagram" };
const pad = id => String(id).padStart(4, "0");

// Customer-facing messages (Tunisian Derja, like the AI's own suggested replies).
const ASK_LABELS = {
  customer_name: "الإسم",
  phone: "نمرة التليفون",
  city: "الولاية / المدينة",
  address: "العنوان",
  product: "المنتج"
};

const FIELD_NAME = { customer_name: "name", phone: "phone", city: "city", address: "address" };

const askText = fields =>
  `مرحبا 👋 باش نكمل الطلبية متاعك نحتاج:\n${fields.map(f => `- ${ASK_LABELS[f] || f}`).join("\n")}\nبرشا شكرا!`;

function confirmationText(orderId) {
  const items = db.prepare(
    "SELECT product, variant, quantity, unit_price FROM order_items WHERE order_id = ? ORDER BY id"
  ).all(orderId);

  const lines = items
    .map(item => `- ${item.product}${item.variant ? ` (${item.variant})` : ""} × ${item.quantity}`)
    .join("\n");
  const total = Number(items.reduce((sum, item) => sum + item.quantity * item.unit_price, 0).toFixed(3));

  return `✅ طلبيتك تسجّلت (#${pad(orderId)})\n${lines}\nالمجموع: ${total} د.ت\nباش نعيطولك قريب للتأكيد. شكرا برشا 🙏`;
}

// What the automation last wrote into an order's items: if they still match, the seller has not changed them.
const itemsSnapshot = orderId => JSON.stringify(
  db.prepare("SELECT product, variant, quantity FROM order_items WHERE order_id = ? ORDER BY id").all(orderId)
);

// Never lets a failed reply break an order that was already saved.
async function autoReply(connection, threadId, text) {
  if (process.env.META_AUTO_REPLY === "0") return;

  const thread = db.prepare("SELECT * FROM meta_threads WHERE id = ?").get(threadId);
  const current = db.prepare("SELECT status FROM meta_connections WHERE id = ?").get(connection.id);

  if (!thread || current?.status !== "active") return;
  if (Date.now() - thread.last_inbound_at >= MESSAGING_WINDOW_MS) return; // Meta's 24-hour rule
  if (text === thread.last_auto_reply) return;                            // never repeat the same message

  try {
    await sendText(connection, thread, text);
    db.prepare("UPDATE meta_threads SET last_auto_reply = ? WHERE id = ?").run(text, thread.id);
    console.log(`Auto reply sent on thread ${thread.id}`);
  } catch (error) {
    markNeedsReconnect(error, connection);
    console.error("Auto reply failed:", error.message);
  }
}

// Reasons the SELLER has to look at an order (the customer is not bothered with these).
function aiBlockers(result, isNewDraft) {
  const blockers = [];

  if (result.provider === "rules") blockers.push("AI offline: verify manually");

  const minConfidence = Number(process.env.META_AUTO_MIN_CONFIDENCE ?? 0.6);
  if (result.confidence != null && result.confidence < minConfidence) blockers.push("low confidence");

  if (isNewDraft && result.customer_intent !== "new_order") blockers.push("unclear whether this is an order");

  return blockers;
}

async function autoProcessThread(threadId) {
  const thread = db.prepare("SELECT * FROM meta_threads WHERE id = ?").get(threadId);
  if (!thread) return;

  const connection = db.prepare("SELECT * FROM meta_connections WHERE id = ?").get(thread.connection_id);
  if (!connection) return;

  // Only customer messages that are not already part of a finished order.
  const rows = db.prepare(
    "SELECT id, text FROM meta_messages WHERE thread_id = ? AND direction = 'in' AND id > ? ORDER BY id DESC LIMIT 10"
  ).all(thread.id, thread.order_cutoff || 0).reverse();

  if (!rows.length) return;

  const text = rows.map(row => row.text).join("\n").slice(-2000);
  const lastId = rows[rows.length - 1].id;
  const uid = connection.user_id;

  const products = db.prepare("SELECT id, name, price, aliases FROM products WHERE user_id = ? ORDER BY name").all(uid);

  let result;
  try {
    result = await analyzeMessage(text, { products });
  } catch (error) {
    console.error("Auto order: AI analysis failed:", error.message);
    return;
  }

  const items = (result.items || []).filter(item => item.product);
  const intent = result.customer_intent;
  const extracted = result.extracted || {};

  // This conversation has an open draft only if it says so AND the order is still a pending draft (checked again by the database).
  const isOpen = Boolean(thread.order_id) && (thread.auto_status === "draft" || thread.auto_status === "needs_review");

  const summary = JSON.stringify({
    intent,
    confidence: result.confidence ?? null,
    extracted: {
      customer_name: extracted.customer_name || "",
      phone: extracted.phone || "",
      city: extracted.city || "",
      address: extracted.address || ""
    },
    items: items.map(item => ({ product: item.product, quantity: item.quantity || 1, variant: item.variant || "" }))
  });

  const chatReply = result.suggested_reply
    && (intent === "question" || intent === "other")
    && result.provider !== "rules"
    && process.env.META_AUTO_REPLY_CHAT !== "0";

  // ---------- Not an order (and no draft waiting): chat or a question ----------
  if (!isOpen && (!items.length || intent === "question" || intent === "complaint")) {
    const finished = thread.auto_status === "order_created"; // keep the badge of the order just saved

    db.prepare("UPDATE meta_threads SET auto_status = ?, auto_note = ?, analyzed_upto = ?, last_result = ? WHERE id = ?")
      .run(
        finished ? thread.auto_status : "not_order",
        finished ? thread.auto_note : "",
        lastId,
        finished ? thread.last_result : summary,
        thread.id
      );

    emit(uid, { type: "thread_updated", thread_id: thread.id });
    console.log(`Auto order: thread ${thread.id} -> not an order`);

    if (chatReply) await autoReply(connection, thread.id, result.suggested_reply);
    return;
  }

  // ---------- Order: create the draft, or complete the one this conversation owns ----------
  const openOrderId = isOpen ? thread.order_id : null;
  const blockers = aiBlockers(result, !openOrderId);

  // A Facebook / Instagram profile name stands in for a name the customer never gave (an @handle is not a name).
  const fallbackName = thread.customer_name && !thread.customer_name.startsWith("@") ? thread.customer_name : "";

  const out = autoOrderHandler(uid, {
    threadId: thread.id,
    openOrderId,
    fields: {
      customer_name: extracted.customer_name,
      phone: extracted.phone,
      city: extracted.city,
      address: extracted.address
    },
    items: items.map(item => ({
      product: item.product,
      variant: item.variant || "",
      color: item.color || "",
      size: item.size || "",
      quantity: item.quantity || 1,
      unit_price: item.unit_price || 0
    })),
    message: text,
    source: SOURCE_NAME[connection.platform] || "manual",
    replaceItems: Boolean(openOrderId) && itemsSnapshot(openOrderId) === thread.draft_items,
    fallbackName,
    canComplete: blockers.length === 0,
    requireAddress: process.env.META_AUTO_REQUIRE_ADDRESS === "1"
  });

  // The draft was deleted, or the seller confirmed / cancelled it: it is closed. What the customer
  // writes from now on starts from the first message that was not analysed yet (never from the old text).
  if (!out.ok && out.gone) {
    db.prepare(
      "UPDATE meta_threads SET order_id = NULL, auto_status = '', auto_note = '', draft_items = '', order_cutoff = ? WHERE id = ?"
    ).run(thread.analyzed_upto || 0, thread.id);

    return autoProcessThread(threadId);
  }

  if (!out.ok) {
    db.prepare("UPDATE meta_threads SET auto_status = 'needs_review', auto_note = ?, analyzed_upto = ?, last_result = ? WHERE id = ?")
      .run(out.reason || "could not save", lastId, summary, thread.id);
    emit(uid, { type: "thread_updated", thread_id: thread.id });
    console.log(`Auto order: thread ${thread.id} -> needs_review (${out.reason})`);
    return;
  }

  const orderId = out.order_id;
  const missing = out.missing;

  const issues = [...blockers];
  if (out.unpriced) issues.push("product not in catalog or without a price");
  if (out.duplicate_id) issues.push(`possible duplicate of order #${pad(out.duplicate_id)}`);

  const waiting = missing.length ? `waiting for: ${missing.map(f => FIELD_NAME[f] || f).join(", ")}` : "";

  let status;
  let note;

  if (out.complete) {
    status = "order_created";
    note = "";
  } else if (issues.length) {
    status = "needs_review";
    note = [...issues, waiting].filter(Boolean).join(" · ");
  } else {
    status = "draft";
    note = waiting;
  }

  db.prepare(`
    UPDATE meta_threads
    SET auto_status = ?, auto_note = ?, order_id = ?, analyzed_upto = ?, last_result = ?,
        order_cutoff = ?, draft_items = ?
    WHERE id = ?
  `).run(
    status, note, orderId, lastId, summary,
    out.complete ? lastId : thread.order_cutoff,   // a finished order closes: the next one starts after it
    out.complete ? "" : itemsSnapshot(orderId),
    thread.id
  );

  emit(uid, { type: out.created ? "order_created" : "order_updated", thread_id: thread.id, order_id: orderId });
  emit(uid, { type: "thread_updated", thread_id: thread.id });
  console.log(`Auto order: thread ${thread.id} -> ${status} #${orderId}${out.created ? " (new)" : ""}${note ? ` (${note})` : ""}`);

  // ---------- Answer the customer ----------
  if (out.complete) {
    await autoReply(connection, thread.id, confirmationText(orderId));
  } else if (!issues.length && missing.length) {
    const answer = intent === "question" && chatReply ? result.suggested_reply : askText(missing);
    await autoReply(connection, thread.id, answer);
  }
}

export function processWebhook(payload) {
  const platform = payload?.object === "instagram" ? "instagram" : payload?.object === "page" ? "facebook" : null;
  if (!platform) return;

  console.log(`Meta webhook payload: object=${payload.object}, entries=${(payload.entry || []).map(e => e.id).join(",")}`);

  for (const entry of payload.entry || []) {
    const connection = db.prepare(
      "SELECT * FROM meta_connections WHERE platform = ? AND account_id = ? AND status != 'removed'"
    ).get(platform, String(entry.id));

    if (!connection) {
      console.log(`Meta webhook: no connection found for ${platform} account ${entry.id}`);
      continue;
    }

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
        if (!isEcho) scheduleAutoOrder(thread.id);
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
           t.last_message, t.last_message_at, t.last_inbound_at, t.unread,
           t.auto_status, t.auto_note, t.order_id, t.last_result
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
    const sent = await sendText(connection, thread, parsed.data.text);

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
