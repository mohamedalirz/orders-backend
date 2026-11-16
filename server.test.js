import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { tempDb, fakeGroq, listen } from "./testkit.js";

tempDb();
const groq = await fakeGroq();
const { app, db } = await import("./server.js");
const { server, call } = await listen(app);

let T; // token of the logged-in test user
const api = (m, p, b) => call(m, p, b, T);

before(async () => {
  const r = await call("POST", "/api/auth/register", { name: "Sara", store_name: "Sara Shop", email: "sara@test.com", password: "password123" });
  assert.equal(r.status, 201);
  T = r.body.token;
  await api("POST", "/api/products", { name: "Robe Lina", price: 59, aliases: "robe lina, روبة لينا" });
  await api("POST", "/api/products", { name: "Sac handmade", price: 45, aliases: "sac, sacs" });
});
after(() => { server.close(); groq.server.close(); db.close(); });

const order = (o = {}) => ({
  customer_name: "Test", phone: "+216 22 123 456", city: "Tunis",
  items: [{ product: "Robe", quantity: 1, unit_price: 50 }], ...o
});

test("every data route needs a login", async () => {
  for (const p of ["/api/orders", "/api/products", "/api/stats", "/api/extractions", "/api/ai/status"]) {
    assert.equal((await call("GET", p)).status, 401, p);
  }
  assert.equal((await call("GET", "/api/health")).status, 200);
});

test("create normalizes phone, totals, blocks duplicate, force works", async () => {
  const a = await api("POST", "/api/orders", order());
  assert.equal(a.status, 201);
  assert.equal(a.body.phone, "22123456");
  assert.equal(a.body.total, 50);
  const dup = await api("POST", "/api/orders", order());
  assert.equal(dup.status, 409);
  assert.equal(dup.body.duplicate_id, a.body.id);
  assert.equal((await api("POST", "/api/orders?force=1", order())).status, 201);
});

test("validation", async () => {
  assert.equal((await api("POST", "/api/orders", order({ phone: "123" }))).status, 400);
  assert.equal((await api("POST", "/api/orders", order({ items: [] }))).status, 400);
  assert.equal((await api("POST", "/api/orders", order({ items: [{ product: "x", quantity: 1.5, unit_price: 1 }] }))).status, 400);
  assert.equal((await api("POST", "/api/orders", order({ status: "bogus" }))).status, 400);
});

test("legacy flat product accepted", async () => {
  const r = await api("POST", "/api/orders", { customer_name: "L", phone: "98111333", city: "Sfax", product: "Sac", quantity: 2, unit_price: 10 });
  assert.equal(r.status, 201);
  assert.equal(r.body.total, 20);
});

test("patch only changes sent fields", async () => {
  const a = await api("POST", "/api/orders", order({ phone: "55999888", address: "Rue 1", source: "Instagram" }));
  const p = await api("PATCH", `/api/orders/${a.body.id}`, { status: "confirmed" });
  assert.equal(p.status, 200);
  assert.equal(p.body.status, "confirmed");
  assert.equal(p.body.address, "Rue 1");
  assert.equal(p.body.source, "Instagram");
  const q = await api("PATCH", `/api/orders/${a.body.id}`, { items: [{ product: "A", quantity: 2, unit_price: 5 }, { product: "B", quantity: 1, unit_price: 3 }] });
  assert.equal(q.body.total, 13);
  assert.equal(q.body.items.length, 2);
  assert.equal((await api("PATCH", `/api/orders/${a.body.id}`, {})).status, 400);
  assert.equal((await api("PATCH", "/api/orders/99999", { status: "confirmed" })).status, 404);
  assert.equal((await api("PATCH", "/api/orders/abc", { status: "confirmed" })).status, 400);
});

test("risk level from returns", async () => {
  const phone = "29111222";
  for (const status of ["returned", "cancelled"]) await api("POST", "/api/orders?force=1", order({ phone, status }));
  const r = await api("POST", "/api/orders?force=1", order({ phone }));
  assert.equal(r.body.risk_level, "high");
});

test("delete + search", async () => {
  const a = await api("POST", "/api/orders", order({ phone: "27111000", customer_name: "Zorro 100%" }));
  assert.equal((await api("GET", "/api/orders?q=zorro%20100%25")).body.length, 1);
  assert.equal((await api("DELETE", `/api/orders/${a.body.id}`)).status, 200);
  assert.equal((await api("DELETE", `/api/orders/${a.body.id}`)).status, 404);
});

test("products CRUD", async () => {
  const c = await api("POST", "/api/products", { name: "Veste", price: 80, aliases: "jacket" });
  assert.equal(c.status, 201);
  assert.equal((await api("POST", "/api/products", { name: "veste", price: 1 })).status, 409);
  assert.equal((await api("PATCH", `/api/products/${c.body.id}`, { name: "Veste", price: 90 })).body.price, 90);
  assert.equal((await api("DELETE", `/api/products/${c.body.id}`)).status, 200);
});

test("stats", async () => {
  const r = await api("GET", "/api/stats");
  assert.equal(r.status, 200);
  assert.ok(r.body.total >= 3 && "revenue" in r.body);
});

test("bad json and big body give JSON errors", async () => {
  const bad = await fetch(`http://127.0.0.1:${server.address().port}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: "{oops" });
  assert.equal(bad.status, 400);
  assert.ok((await bad.json()).error);
  assert.equal((await api("POST", "/api/orders", { x: "a".repeat(200000) })).status, 413);
});

test("extract: AI result is validated, and saved in the database", async () => {
  groq.state.status = 200;
  groq.state.reply = {
    customer_intent: "new_order", customer_name: "Amira", phone: "99999999", city: "Sousse", address: "",
    items: [{ product: "robe lina", color: "noir", size: "M", quantity: 2 }], suggested_reply: ""
  };
  const r = await api("POST", "/api/extract", { message: "nheb 2 robe lina noir M, Amira, nemrti 22 123 456, Tunis" });
  assert.equal(r.status, 200);
  assert.equal(r.body.source, "groq");
  assert.equal(r.body.extracted.phone, "22123456");
  assert.equal(r.body.extracted.city, "Tunis");
  assert.equal(r.body.items[0].product, "Robe Lina");
  assert.equal(r.body.items[0].unit_price, 59);
  assert.ok(r.body.extraction_id);

  const history = await api("GET", "/api/extractions");
  assert.equal(history.body[0].id, r.body.extraction_id);
  assert.match(history.body[0].message, /robe lina/);
  assert.equal(history.body[0].result.items[0].product, "Robe Lina");
  assert.equal((await api("DELETE", `/api/extractions/${r.body.extraction_id}`)).status, 200);
});

test("extract: falls back to rules when Groq is down", async () => {
  groq.state.status = 500;
  const r = await api("POST", "/api/extract", { message: "nheb sac, nemrti 55 123 456, Sfax" });
  assert.equal(r.status, 200);
  assert.equal(r.body.source, "rules");
  assert.ok(r.body.warning);
  assert.equal(r.body.extracted.phone, "55123456");
  groq.state.status = 200;
});

test("extract: input limits", async () => {
  assert.equal((await api("POST", "/api/extract", { message: "" })).status, 400);
  assert.equal((await api("POST", "/api/extract", { message: "a".repeat(2001) })).status, 400);
});

test("extract: garbage AI output does not crash", async () => {
  groq.state.reply = [1, 2];
  assert.equal((await api("POST", "/api/extract", { message: "salam" })).status, 200);
});
