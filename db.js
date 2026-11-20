
// The database: one SQLite file. Everything the website saves lives here.
//
//   users        accounts (email + hashed password + store name)
//   sessions     who is logged in (token hash + expiry)
//   orders       one row per order, owned by a user
//   order_items  the products inside each order
//   products     each user's catalog
//   extractions  AI extraction history
//
// Old databases are upgraded automatically when the server starts.

import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { normalizePhone, isValidTnPhone } from "./tunisia.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const dbPath =
  process.env.DB_PATH || path.join(__dirname, "data", "talab.db");

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

export const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

const columns = table =>
  db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);

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
// OLD DATABASES: PRODUCTS
// Products used one global unique name.
// Now names are unique per user.
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

      INSERT INTO products (
        id,
        user_id,
        name,
        price,
        aliases,
        created_at
      )
      SELECT
        id,
        NULL,
        name,
        price,
        aliases,
        created_at
      FROM products_old;

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

// --------------------------------------------------
// LEGACY ORDERS: ADD USER OWNERSHIP
// --------------------------------------------------

if (!columns("orders").includes("user_id")) {
  db.exec(`
    ALTER TABLE orders
    ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE
  `);
}

// --------------------------------------------------
// AI ORDER DRAFTS + META CONVERSATION ASSOCIATION
// --------------------------------------------------

const orderColumns = columns("orders");

// Draft or complete.
//
// Existing orders automatically become "complete".
// Operational status remains separate from order_state.

if (!orderColumns.includes("order_state")) {
  db.exec(`
    ALTER TABLE orders
    ADD COLUMN order_state TEXT NOT NULL DEFAULT 'complete'
  `);
}

// Exact Meta conversation associated with this order.
// This is deliberately not a foreign key because Meta tables
// are initialized separately in meta.js.

if (!orderColumns.includes("meta_thread_id")) {
  db.exec(`
    ALTER TABLE orders
    ADD COLUMN meta_thread_id INTEGER
  `);
}

// Original Meta message responsible for creating the order.
// Used for idempotency and duplicate webhook protection.

if (!orderColumns.includes("meta_source_message_id")) {
  db.exec(`
    ALTER TABLE orders
    ADD COLUMN meta_source_message_id TEXT
  `);
}

// Last time an AI draft was modified.

if (!orderColumns.includes("draft_updated_at")) {
  db.exec(`
    ALTER TABLE orders
    ADD COLUMN draft_updated_at TEXT
  `);
}

// --------------------------------------------------
// INDEXES
// --------------------------------------------------

db.exec(`
CREATE INDEX IF NOT EXISTS idx_orders_user
ON orders(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_orders_phone
ON orders(user_id, phone);

CREATE INDEX IF NOT EXISTS idx_orders_meta_thread_state
ON orders(user_id, meta_thread_id, order_state);

CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_meta_source_message
ON orders(user_id, meta_source_message_id)
WHERE meta_source_message_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_items_order
ON order_items(order_id);

CREATE INDEX IF NOT EXISTS idx_products_user
ON products(user_id);

CREATE INDEX IF NOT EXISTS idx_extractions_user
ON extractions(user_id, id);

CREATE INDEX IF NOT EXISTS idx_sessions_user
ON sessions(user_id);
`);

// --------------------------------------------------
// OLD DATABASES: MAKE SURE EVERY ORDER HAS ITS ITEMS
// --------------------------------------------------

db.prepare(`
  INSERT INTO order_items (
    order_id,
    product,
    variant,
    quantity,
    unit_price
  )
  SELECT
    o.id,
    o.product,
    o.variant,
    o.quantity,
    o.unit_price
  FROM orders o
  WHERE NOT EXISTS (
    SELECT 1
    FROM order_items oi
    WHERE oi.order_id = o.id
  )
`).run();

// --------------------------------------------------
// NORMALIZE EXISTING TUNISIAN PHONE NUMBERS
// --------------------------------------------------

db.transaction(() => {
  const update = db.prepare(
    "UPDATE orders SET phone = ? WHERE id = ?"
  );

  for (const row of db.prepare(
    "SELECT id, phone FROM orders"
  ).all()) {
    const clean = normalizePhone(row.phone);

    if (clean !== row.phone && isValidTnPhone(clean)) {
      update.run(clean, row.id);
    }
  }
})();

// --------------------------------------------------
// CLEAN EXPIRED SESSIONS
// --------------------------------------------------

db.prepare(
  "DELETE FROM sessions WHERE expires_at < ?"
).run(Date.now());
