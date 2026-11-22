import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";
import { tempDb, fakeGroq, listen } from "./testkit.js";

// A fake Meta Graph API, so no real Facebook account is needed.
const sent = [];
const graph = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  let body = "";
  req.on("data", c => (body += c));
  req.on("end", () => {
    res.setHeader("content-type", "application/json");
    const p = url.pathname.replace(/^\/v\d+\.\d+/, "");
    if (p === "/oauth/access_token") return res.end(JSON.stringify({ access_token: "tok" }));
    if (p === "/me") return res.end(JSON.stringify({ id: "FBUSER1" }));
    if (p === "/me/accounts") {
      return res.end(JSON.stringify({ data: [{ id: "P1", name: "Sara Page", access_token: "PAGE_TOKEN",
        instagram_business_account: { id: "IG1", username: "sara_shop" } }] }));
    }
    if (p === "/P1/subscribed_apps") return res.end(JSON.stringify({ success: true }));
    if (p === "/P1/messages") { sent.push(JSON.parse(body)); return res.end(JSON.stringify({ recipient_id: "C1", message_id: "m_out_1" })); }
    if (p === "/C1") return res.end(JSON.stringify({ name: "Ahmed Ben Ali" }));
    res.statusCode = 404; res.end(JSON.stringify({ error: { message: "nope", code: 100 } }));
  });
});
await new Promise(r => graph.listen(0, "127.0.0.1", r));

await tempDb();
Object.assign(process.env, {
  META_APP_ID: "123", META_APP_SECRET: "secret", META_VERIFY_TOKEN: "verify-me",
  META_REDIRECT_URI: "https://api.example.com/api/meta/callback",
  META_TOKEN_KEY: crypto.randomBytes(32).toString("base64"),
  META_GRAPH_BASE: `http://127.0.0.1:${graph.address().port}`,
  FRONTEND_ORIGIN: "http://localhost:5173"
});

const groq = await fakeGroq();
const { app, db } = await import("./server.js");
const { webhooksIdle } = await import("./meta.js");
const { server, base, call } = await listen(app);

let T;
const api = (m, p, b) => call(m, p, b, T);

const signed = async payload => {
  const raw = JSON.stringify(payload);
  const response = await fetch(`${base}/api/meta/webhook`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-hub-signature-256": "sha256=" + crypto.createHmac("sha256", "secret").update(raw).digest("hex") },
    body: raw
  });
  await webhooksIdle(); // the server answers first, then stores the message
  return response;
};

const inbound = (mid, text, ts = Date.now()) => ({
  object: "page",
  entry: [{ id: "P1", messaging: [{ sender: { id: "C1" }, recipient: { id: "P1" }, timestamp: ts, message: { mid, text } }] }]
});

before(async () => {
  const r = await call("POST", "/api/auth/register", { name: "Sara", store_name: "Shop", email: "s@test.com", password: "password123" });
  T = r.body.token;
});
after(async () => { server.close(); graph.close(); groq.server.close(); await db.close(); });

test("connect needs login, then OAuth callback stores Page + Instagram", async () => {
  assert.equal((await call("POST", "/api/meta/connect")).status, 401);

  const { body } = await api("POST", "/api/meta/connect");
  const state = new URL(body.url).searchParams.get("state");
  assert.ok(state);

  const bad = await fetch(`${base}/api/meta/callback?code=abc&state=forged`, { redirect: "manual" });
  assert.match(bad.headers.get("location"), /meta=invalid_state/);

  const ok = await fetch(`${base}/api/meta/callback?code=abc&state=${state}`, { redirect: "manual" });
  assert.match(ok.headers.get("location"), /meta=connected/);

  // The state works only once.
  const again = await fetch(`${base}/api/meta/callback?code=abc&state=${state}`, { redirect: "manual" });
  assert.match(again.headers.get("location"), /meta=invalid_state/);

  const status = await api("GET", "/api/meta/status");
  assert.deepEqual(status.body.connections.map(c => c.platform), ["facebook", "instagram"]);

  // Token is encrypted in the database and never returned by the API.
  const row = await db.prepare("SELECT token_enc FROM meta_connections").get();
  assert.ok(!row.token_enc.includes("PAGE_TOKEN"));
  assert.ok(!JSON.stringify(status.body).includes("token"));
});

test("webhook verification handshake", async () => {
  const good = await fetch(`${base}/api/meta/webhook?hub.mode=subscribe&hub.verify_token=verify-me&hub.challenge=777`);
  assert.equal(await good.text(), "777");
  assert.equal((await fetch(`${base}/api/meta/webhook?hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=1`)).status, 403);
});

test("webhook rejects a bad signature, stores a good one once", async () => {
  const forged = await fetch(`${base}/api/meta/webhook`, {
    method: "POST", headers: { "content-type": "application/json", "x-hub-signature-256": "sha256=deadbeef" },
    body: JSON.stringify(inbound("m1", "hi"))
  });
  assert.equal(forged.status, 403);

  assert.equal((await signed(inbound("m1", "Salam, nheb robe lina"))).status, 200);
  assert.equal((await signed(inbound("m1", "Salam, nheb robe lina"))).status, 200); // Meta retry

  const threads = await api("GET", "/api/meta/threads");
  assert.equal(threads.body.length, 1);
  assert.equal(threads.body[0].unread, 1);
  assert.equal(threads.body[0].can_reply, true);

  await new Promise(r => setTimeout(r, 100)); // customer name is fetched in the background
  const msgs = await api("GET", `/api/meta/threads/${threads.body[0].id}/messages`);
  assert.equal(msgs.body.messages.length, 1);
  assert.equal(msgs.body.thread.customer_name, "Ahmed Ben Ali");
});

test("reply goes through Meta and the echo is not duplicated", async () => {
  const [t] = (await api("GET", "/api/meta/threads")).body;

  const r = await api("POST", `/api/meta/threads/${t.id}/reply`, { text: "Marhba! 59 TND" });
  assert.equal(r.status, 201);
  assert.deepEqual(sent[0].recipient, { id: "C1" });
  assert.equal(sent[0].messaging_type, "RESPONSE");

  await signed({ object: "page", entry: [{ id: "P1", messaging: [{ sender: { id: "P1" }, recipient: { id: "C1" }, timestamp: Date.now(),
    message: { mid: "m_out_1", text: "Marhba! 59 TND", is_echo: true } }] }] });

  const msgs = await api("GET", `/api/meta/threads/${t.id}/messages`);
  assert.deepEqual(msgs.body.messages.map(m => m.direction), ["in", "out"]);
  assert.equal((await api("POST", `/api/meta/threads/${t.id}/reply`, { text: "  " })).status, 400);
});

test("24-hour window blocks late replies; another seller cannot see the thread", async () => {
  const [t] = (await api("GET", "/api/meta/threads")).body;
  await db.prepare("UPDATE meta_threads SET last_inbound_at = ? WHERE id = ?").run(Date.now() - 25 * 3600_000, t.id);
  assert.equal((await api("POST", `/api/meta/threads/${t.id}/reply`, { text: "late" })).status, 409);

  await db.prepare("INSERT INTO users (email, name, store_name, password_hash) VALUES ('o@t.com','O','O','x')").run();
  const other = (await db.prepare("SELECT id FROM users WHERE email='o@t.com'").get()).id;
  const tok = "othertoken";
  await db.prepare("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)")
    .run(other, crypto.createHash("sha256").update(tok).digest("hex"), Date.now() + 100000);
  assert.equal((await call("GET", `/api/meta/threads/${t.id}/messages`, undefined, tok)).status, 404);
  assert.equal((await call("GET", "/api/meta/threads", undefined, tok)).body.length, 0);
});

const signedRequest = data => {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  const sig = crypto.createHmac("sha256", "secret").update(payload).digest("base64url");
  return `${sig}.${payload}`;
};
const form = body => ({ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(body) });

test("postbacks count as customer messages; history is paginated; thread can be deleted", async () => {
  const [t] = (await api("GET", "/api/meta/threads")).body;

  await signed({ object: "page", entry: [{ id: "P1", messaging: [{ sender: { id: "C1" }, recipient: { id: "P1" },
    timestamp: Date.now(), postback: { mid: "pb1", title: "Commander", payload: "ORDER" } }] }] });
  for (let i = 0; i < 4; i++) await signed(inbound(`bulk${i}`, `msg ${i}`));

  const page1 = await api("GET", `/api/meta/threads/${t.id}/messages?limit=3`);
  assert.equal(page1.body.messages.length, 3);
  assert.equal(page1.body.has_more, true);
  assert.equal(page1.body.messages.at(-1).text, "msg 3");

  const page2 = await api("GET", `/api/meta/threads/${t.id}/messages?limit=100&before=${page1.body.messages[0].id}`);
  assert.equal(page2.body.has_more, false);
  assert.ok(page2.body.messages.some(m => m.text === "Commander"));

  assert.equal((await api("DELETE", `/api/meta/threads/${t.id}`)).status, 200);
  assert.equal((await api("GET", "/api/meta/threads")).body.length, 0);
});

test("live stream: ticket is one-time and new messages are pushed", async () => {
  assert.equal((await fetch(`${base}/api/meta/stream?ticket=forged`)).status, 401);
  assert.equal((await call("POST", "/api/meta/stream-ticket")).status, 401);

  const { body } = await api("POST", "/api/meta/stream-ticket");
  const controller = new AbortController();
  const stream = await fetch(base + body.url, { signal: controller.signal });
  assert.equal(stream.status, 200);
  assert.match(stream.headers.get("content-type"), /text\/event-stream/);

  // The same ticket cannot be used twice.
  assert.equal((await fetch(base + body.url)).status, 401);

  await signed(inbound("live1", "hello live"));

  const reader = stream.body.getReader();
  let text = "";
  while (!text.includes('"type":"message"')) {
    const { value, done } = await reader.read();
    if (done) break;
    text += Buffer.from(value).toString();
  }
  controller.abort();
  assert.match(text, /"direction":"in"/);
});

test("deauthorize and data-deletion callbacks verify the signature", async () => {
  const bad = await fetch(`${base}/api/meta/data-deletion`, form({ signed_request: "abc.def" }));
  assert.equal(bad.status, 400);

  const dea = await fetch(`${base}/api/meta/deauthorize`, form({ signed_request: signedRequest({ user_id: "FBUSER1" }) }));
  assert.equal(dea.status, 200);
  assert.equal((await api("GET", "/api/meta/status")).body.connections[0].status, "needs_reconnect");
  const blocked = (await api("GET", "/api/meta/threads")).body;
  assert.equal(blocked.length, 1); // the live-stream test created a new thread

  const del = await fetch(`${base}/api/meta/data-deletion`, form({ signed_request: signedRequest({ user_id: "FBUSER1" }) }));
  assert.equal(del.status, 200);
  const out = await del.json();
  assert.ok(out.confirmation_code);
  assert.match(out.url, /\/api\/meta\/deletion-status\?code=/);

  assert.equal((await api("GET", "/api/meta/status")).body.connections.length, 0);
  assert.equal((await api("GET", "/api/meta/threads")).body.length, 0);
  assert.equal((await db.prepare("SELECT COUNT(*) n FROM meta_messages").get()).n, 0);

  const page = await fetch(`${base}/api/meta/deletion-status?code=${out.confirmation_code}`);
  assert.equal(page.status, 200);
  assert.equal((await fetch(`${base}/api/meta/deletion-status?code=nope`)).status, 404);
});
