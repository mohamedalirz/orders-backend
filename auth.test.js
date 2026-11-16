import test, { after } from "node:test";
import assert from "node:assert/strict";
import Database from "better-sqlite3";
import { tempDb, listen } from "./testkit.js";

// An OLD database, from before accounts existed: global-unique products, orders without owner.
const file = tempDb();
{
  const old = new Database(file);
  old.exec(`
    CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_name TEXT NOT NULL, phone TEXT NOT NULL, city TEXT NOT NULL,
      address TEXT DEFAULT '', product TEXT NOT NULL, variant TEXT DEFAULT '', quantity INTEGER NOT NULL DEFAULT 1,
      unit_price REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending', delivery_status TEXT NOT NULL DEFAULT 'not_sent',
      cod_status TEXT NOT NULL DEFAULT 'not_received', source TEXT NOT NULL DEFAULT 'manual', message TEXT DEFAULT '',
      risk_level TEXT NOT NULL DEFAULT 'low', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
      price REAL NOT NULL DEFAULT 0, aliases TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    INSERT INTO orders (customer_name, phone, city, product, quantity, unit_price) VALUES ('Old Customer', '+216 22 123 456', 'Tunis', 'Robe', 1, 59);
    INSERT INTO products (name, price) VALUES ('Robe', 59);
  `);
  old.close();
}

const { app, db } = await import("./server.js");
const { server, call } = await listen(app);
after(() => { server.close(); db.close(); });

const ana = { name: "Ana", store_name: "Ana Store", email: "Ana@Test.com", password: "password123" };

test("old database is upgraded and still unreadable without login", async () => {
  assert.equal((await call("GET", "/api/orders")).status, 401);
  const status = await call("GET", "/api/auth/status");
  assert.deepEqual(status.body, { hasUsers: false, signupOpen: true });
});

test("registration validation", async () => {
  assert.equal((await call("POST", "/api/auth/register", { ...ana, password: "short" })).status, 400);
  assert.equal((await call("POST", "/api/auth/register", { ...ana, email: "nope" })).status, 400);
  assert.equal((await call("POST", "/api/auth/register", { ...ana, name: "" })).status, 400);
});

let tokenAna;

test("first account takes over the old data", async () => {
  const r = await call("POST", "/api/auth/register", ana);
  assert.equal(r.status, 201);
  assert.equal(r.body.user.email, "ana@test.com");
  assert.equal(r.body.user.store_name, "Ana Store");
  assert.equal(r.body.user.password_hash, undefined);
  tokenAna = r.body.token;

  const orders = await call("GET", "/api/orders", undefined, tokenAna);
  assert.equal(orders.body.length, 1);
  assert.equal(orders.body[0].customer_name, "Old Customer");
  assert.equal(orders.body[0].phone, "22123456"); // normalized by the upgrade
  assert.equal((await call("GET", "/api/products", undefined, tokenAna)).body.length, 1);
});

test("password is stored hashed, token only as a hash", () => {
  const user = db.prepare("SELECT * FROM users").get();
  assert.match(user.password_hash, /^scrypt\$/);
  assert.ok(!user.password_hash.includes("password123"));
  const s = db.prepare("SELECT * FROM sessions").get();
  assert.notEqual(s.token_hash, tokenAna);
  assert.equal(s.token_hash.length, 64);
});

test("sign-ups closed after the first account, open with ALLOW_SIGNUP=1", async () => {
  const other = { name: "Ben", store_name: "Ben Shop", email: "ben@test.com", password: "password123" };
  assert.equal((await call("GET", "/api/auth/status")).body.signupOpen, false);
  assert.equal((await call("POST", "/api/auth/register", other)).status, 403);

  process.env.ALLOW_SIGNUP = "1";
  assert.equal((await call("POST", "/api/auth/register", { ...other, email: "ANA@test.com" })).status, 409);
  const r = await call("POST", "/api/auth/register", other);
  assert.equal(r.status, 201);
  process.env.ALLOW_SIGNUP = "";

  // Ben starts empty and cannot see Ana's data.
  assert.equal((await call("GET", "/api/orders", undefined, r.body.token)).body.length, 0);
  assert.equal((await call("GET", "/api/products", undefined, r.body.token)).body.length, 0);
});

test("accounts are isolated from each other", async () => {
  const ben = (await call("POST", "/api/auth/login", { email: "ben@test.com", password: "password123" })).body.token;

  const orderAna = (await call("GET", "/api/orders", undefined, tokenAna)).body[0];
  const productAna = (await call("GET", "/api/products", undefined, tokenAna)).body[0];

  // Ben cannot read, change or delete Ana's rows (they look like they do not exist).
  assert.equal((await call("PATCH", `/api/orders/${orderAna.id}`, { status: "confirmed" }, ben)).status, 404);
  assert.equal((await call("DELETE", `/api/orders/${orderAna.id}`, undefined, ben)).status, 404);
  assert.equal((await call("PATCH", `/api/products/${productAna.id}`, { name: "X", price: 1 }, ben)).status, 404);
  assert.equal((await call("DELETE", `/api/products/${productAna.id}`, undefined, ben)).status, 404);

  // Same product name is allowed for two different sellers.
  assert.equal((await call("POST", "/api/products", { name: "Robe", price: 70 }, ben)).status, 201);

  // Ben's failed orders never raise the risk of Ana's customers.
  for (const status of ["returned", "returned"]) {
    await call("POST", "/api/orders?force=1", { customer_name: "B", phone: "22123456", city: "Tunis", status, items: [{ product: "Robe", quantity: 1, unit_price: 1 }] }, ben);
  }
  assert.equal((await call("GET", "/api/orders", undefined, tokenAna)).body[0].risk_level, "low");
  assert.equal((await call("GET", "/api/stats", undefined, ben)).body.total, 2);
  assert.equal((await call("GET", "/api/stats", undefined, tokenAna)).body.total, 1);
});

test("login: wrong password, unknown email, bad token", async () => {
  const bad = await call("POST", "/api/auth/login", { email: "ana@test.com", password: "wrong-password" });
  assert.equal(bad.status, 401);
  const unknown = await call("POST", "/api/auth/login", { email: "ghost@test.com", password: "wrong-password" });
  assert.equal(unknown.status, 401);
  assert.equal(bad.body.error, unknown.body.error); // does not reveal which emails exist
  assert.equal((await call("GET", "/api/orders", undefined, "garbage")).status, 401);
});

test("login works with any email capitalisation", async () => {
  const r = await call("POST", "/api/auth/login", { email: " ANA@test.COM ", password: "password123" });
  assert.equal(r.status, 200);
  assert.equal((await call("GET", "/api/auth/me", undefined, r.body.token)).body.user.name, "Ana");
});

test("logout kills the token", async () => {
  const t = (await call("POST", "/api/auth/login", { email: "ana@test.com", password: "password123" })).body.token;
  assert.equal((await call("GET", "/api/auth/me", undefined, t)).status, 200);
  assert.equal((await call("POST", "/api/auth/logout", {}, t)).status, 200);
  assert.equal((await call("GET", "/api/auth/me", undefined, t)).status, 401);
});

test("expired session is refused", async () => {
  const t = (await call("POST", "/api/auth/login", { email: "ana@test.com", password: "password123" })).body.token;
  db.prepare("UPDATE sessions SET expires_at = ?").run(Date.now() - 1000);
  assert.equal((await call("GET", "/api/auth/me", undefined, t)).status, 401);
  // restore a valid session for the next tests
  tokenAna = (await call("POST", "/api/auth/login", { email: "ana@test.com", password: "password123" })).body.token;
});

test("profile update", async () => {
  const r = await call("PATCH", "/api/auth/me", { store_name: "Ana Boutique" }, tokenAna);
  assert.equal(r.body.user.store_name, "Ana Boutique");
  assert.equal(r.body.user.name, "Ana");
  assert.equal((await call("PATCH", "/api/auth/me", { store_name: "" }, tokenAna)).status, 400);
});

test("change password signs out the other devices", async () => {
  const other = (await call("POST", "/api/auth/login", { email: "ana@test.com", password: "password123" })).body.token;
  assert.equal((await call("POST", "/api/auth/password", { current_password: "nope-nope", new_password: "newpassword1" }, tokenAna)).status, 400);
  assert.equal((await call("POST", "/api/auth/password", { current_password: "password123", new_password: "short" }, tokenAna)).status, 400);
  assert.equal((await call("POST", "/api/auth/password", { current_password: "password123", new_password: "newpassword1" }, tokenAna)).status, 200);

  assert.equal((await call("GET", "/api/auth/me", undefined, tokenAna)).status, 200); // this device stays in
  assert.equal((await call("GET", "/api/auth/me", undefined, other)).status, 401);   // the other one is out
  assert.equal((await call("POST", "/api/auth/login", { email: "ana@test.com", password: "password123" })).status, 401);
  assert.equal((await call("POST", "/api/auth/login", { email: "ana@test.com", password: "newpassword1" })).status, 200);
});

test("brute force: 5 wrong passwords lock the account for 15 minutes", async () => {
  for (let i = 0; i < 5; i++) {
    assert.equal((await call("POST", "/api/auth/login", { email: "ben@test.com", password: "bad-password-" + i })).status, 401);
  }
  const locked = await call("POST", "/api/auth/login", { email: "ben@test.com", password: "password123" });
  assert.equal(locked.status, 429);
});
