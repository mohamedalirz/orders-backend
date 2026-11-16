// The database: one SQLite file. Everything the website saves lives here.
//
//   users        accounts (email + hashed password + store name)
//   sessions     who is logged in (token hash + expiry), so logout really works
//   orders       one row per order, owned by a user
//   order_items  the products inside each order
//   products     each user's catalog (name, price, nicknames)
//   extractions  every message you pasted into the AI Inbox, with the AI's answer
//
// Old databases are upgraded automatically the first time the server starts.

import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { normalizePhone, isValidTnPhone } from "./tunisia.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const dbPath = process.env.DB_PATH || path.join(__dirname, "data", "talab.db");

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

export const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

const columns = table => db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);

// --------------------------------------------------
// ACCOUNTS
// --------------------------------------------------

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  store_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  user_agent TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// --------------------------------------------------
// OLD DATABASES: products used one global unique name; now it is unique per user.
// SQLite cannot change that rule in place, so the table is rebuilt once.
// --------------------------------------------------

const oldProducts = columns("products");

if (oldProducts.length && !oldProducts.includes("user_id")) {
  db.transaction(() => {
    db.exec("ALTER TABLE products RENAME TO products_old");

    db.exec(`
      CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL COLLATE NOCASE,
        price REAL NOT NULL DEFAULT 0,
        aliases TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (user_id, name)
      );

      INSERT INTO products (id, user_id, name, price, aliases, created_at)
      SELECT id, NULL, name, price, aliases, created_at FROM products_old;

      DROP TABLE products_old;
    `);
  })();
}

// --------------------------------------------------
// BUSINESS DATA
// --------------------------------------------------

db.exec(`
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  city TEXT NOT NULL,
  address TEXT DEFAULT '',
  product TEXT NOT NULL,
  variant TEXT DEFAULT '',
  quantity INTEGER NOT NULL DEFAULT 1,
  unit_price REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  delivery_status TEXT NOT NULL DEFAULT 'not_sent',
  cod_status TEXT NOT NULL DEFAULT 'not_received',
  source TEXT NOT NULL DEFAULT 'manual',
  message TEXT DEFAULT '',
  risk_level TEXT NOT NULL DEFAULT 'low',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product TEXT NOT NULL,
  variant TEXT DEFAULT '',
  color TEXT DEFAULT '',
  size TEXT DEFAULT '',
  quantity INTEGER NOT NULL DEFAULT 1,
  unit_price REAL NOT NULL DEFAULT 0,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL COLLATE NOCASE,
  price REAL NOT NULL DEFAULT 0,
  aliases TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (user_id, name)
);

CREATE TABLE IF NOT EXISTS extractions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  message TEXT NOT NULL,
  result TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// Orders saved before accounts existed have no owner yet: add the column.
// (The first account that is created takes them over, see auth.js.)
if (!columns("orders").includes("user_id")) {
  db.exec("ALTER TABLE orders ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE");
}

db.exec(`
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_orders_phone ON orders(user_id, phone);
CREATE INDEX IF NOT EXISTS idx_items_order ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_products_user ON products(user_id);
CREATE INDEX IF NOT EXISTS idx_extractions_user ON extractions(user_id, id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
`);

// Older databases: make sure every order has its items.
db.prepare(`
  INSERT INTO order_items (order_id, product, variant, quantity, unit_price)
  SELECT o.id, o.product, o.variant, o.quantity, o.unit_price
  FROM orders o
  WHERE NOT EXISTS (SELECT 1 FROM order_items oi WHERE oi.order_id = o.id)
`).run();

// Older databases: store phones as plain 8 digits so risk detection works.
db.transaction(() => {
  const update = db.prepare("UPDATE orders SET phone = ? WHERE id = ?");

  for (const row of db.prepare("SELECT id, phone FROM orders").all()) {
    const clean = normalizePhone(row.phone);
    if (clean !== row.phone && isValidTnPhone(clean)) update.run(clean, row.id);
  }
})();

// Expired logins are useless: clean them at start-up.
db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(Date.now());
