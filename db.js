// The database: PostgreSQL (free hosting on Neon / Supabase), so nothing is lost when the server restarts.
//
//   users              accounts (email + hashed password + store name)
//   sessions           who is logged in (token hash + expiry)
//   products           each user's catalog (names, prices, colors, sizes)
//   orders             one row per order, owned by a user
//   order_items        the products inside each order
//   extractions        AI extraction history
//   meta_*             Facebook / Instagram connections, conversations and messages
//
// Set DATABASE_URL (the connection string from Neon / Supabase). Tables are created automatically at start.
//
// The helper below keeps the style used everywhere in the code:
//   await db.prepare("SELECT ... WHERE id = ?").get(id)        one row (or undefined)
//   await db.prepare("SELECT ...").all(a, b)                  all rows
//   await db.prepare("INSERT ...").run(a, b)                  { changes, lastInsertRowid }
//   await db.transaction(async () => { ... })()               everything inside is ONE transaction
// Named values work too:  .run({ id, name })  with  @id, @name  in the SQL.

import "dotenv/config";
import pg from "pg";
import { AsyncLocalStorage } from "node:async_hooks";

// COUNT(*) and BIGINT come back as numbers, not strings.
pg.types.setTypeParser(20, Number);
pg.types.setTypeParser(1700, Number);

const url = process.env.DATABASE_URL;

if (!url) {
  throw new Error("DATABASE_URL is missing. Add the Postgres connection string (Neon / Supabase) to the environment.");
}

const local = /@(localhost|127\.0\.0\.1)(:|\/|$)/.test(url);

export const pool = new pg.Pool({
  connectionString: url,
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 15_000,
  ssl: local || process.env.DB_SSL === "off" ? false : { rejectUnauthorized: false }
});

// A dropped idle connection must not crash the server.
pool.on("error", error => console.error("Database pool error:", error.message));

const inTransaction = new AsyncLocalStorage();
const runner = () => inTransaction.getStore() || pool;

// "?" and "@name" -> "$1, $2, ..."   (quoted text is left alone)
function convert(sql, args) {
  const named = args.length === 1 && args[0] && typeof args[0] === "object" && !Array.isArray(args[0]) && !(args[0] instanceof Date);
  const values = [];
  const index = new Map();
  let out = "";
  let quote = null;

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];

    if (quote) {
      out += ch;
      if (ch === quote) quote = null;
      continue;
    }

    if (ch === "'" || ch === '"') { quote = ch; out += ch; continue; }

    if (!named && ch === "?") {
      values.push(args[values.length]);
      out += `$${values.length}`;
      continue;
    }

    if (named && ch === "@" && /[A-Za-z_]/.test(sql[i + 1] || "")) {
      let j = i + 1;
      while (j < sql.length && /\w/.test(sql[j])) j++;
      const name = sql.slice(i + 1, j);
      if (!index.has(name)) {
        if (!(name in args[0])) throw new Error(`Missing SQL value: ${name}`);
        values.push(args[0][name]);
        index.set(name, values.length);
      }
      out += `$${index.get(name)}`;
      i = j - 1;
      continue;
    }

    out += ch;
  }

  if (!named && values.length !== args.length) {
    throw new Error(`SQL has ${values.length} placeholders but ${args.length} values were given`);
  }

  return { text: out, values: values.map(v => (v === undefined ? null : v)) };
}

// Tables whose primary key is "id" (the new id is returned for INSERTs, like lastInsertRowid).
const WITH_ID = new Set([
  "users", "sessions", "products", "orders", "order_items", "extractions",
  "meta_connections", "meta_threads", "meta_messages"
]);

async function execute(sql, args) {
  let text = sql;
  const insert = /^\s*insert\s+into\s+(\w+)/i.exec(text);
  const wantsId = Boolean(insert && WITH_ID.has(insert[1].toLowerCase()) && !/\breturning\b/i.test(text));
  if (wantsId) text = `${text.trimEnd().replace(/;$/, "")} RETURNING id`;

  const q = convert(text, args);
  const result = await runner().query(q.text, q.values);

  return { rows: result.rows, changes: result.rowCount ?? 0, lastInsertRowid: wantsId ? result.rows[0]?.id : undefined };
}

export const db = {
  prepare(sql) {
    return {
      get: async (...args) => (await execute(sql, args)).rows[0],
      all: async (...args) => (await execute(sql, args)).rows,
      run: async (...args) => {
        const { changes, lastInsertRowid } = await execute(sql, args);
        return { changes, lastInsertRowid };
      }
    };
  },

  // Several statements at once, without values (schema changes).
  exec: sql => runner().query(sql),

  // db.transaction(async (...args) => { ... })  returns a function that runs everything on ONE connection:
  // all or nothing. Inside it, db.prepare(...) automatically uses that connection.
  transaction(fn) {
    return async (...args) => {
      if (inTransaction.getStore()) return fn(...args); // already inside one

      const client = await pool.connect();

      try {
        await client.query("BEGIN");
        const result = await inTransaction.run(client, () => fn(...args));
        await client.query("COMMIT");
        return result;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    };
  },

  close: () => pool.end()
};

export const isUniqueViolation = error => error?.code === "23505";

// --------------------------------------------------
// TABLES (created when missing; new columns are added to older tables)
// --------------------------------------------------

const NOW = "(to_char(now() at time zone 'utc', 'YYYY-MM-DD HH24:MI:SS'))";

await db.exec(`
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email CITEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  store_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT ${NOW}
);

CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at BIGINT NOT NULL,
  user_agent TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT ${NOW}
);

CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  name CITEXT NOT NULL,
  price DOUBLE PRECISION NOT NULL DEFAULT 0,
  aliases TEXT NOT NULL DEFAULT '',
  colors TEXT NOT NULL DEFAULT '',
  sizes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT ${NOW},
  UNIQUE (user_id, name)
);

CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,

  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  city TEXT NOT NULL,
  address TEXT DEFAULT '',

  product TEXT NOT NULL,
  variant TEXT DEFAULT '',
  quantity INTEGER NOT NULL DEFAULT 1,
  unit_price DOUBLE PRECISION NOT NULL DEFAULT 0,

  status TEXT NOT NULL DEFAULT 'pending',
  delivery_status TEXT NOT NULL DEFAULT 'not_sent',
  cod_status TEXT NOT NULL DEFAULT 'not_received',

  source TEXT NOT NULL DEFAULT 'manual',
  message TEXT DEFAULT '',
  risk_level TEXT NOT NULL DEFAULT 'low',

  -- orders built from a Facebook / Instagram conversation: which conversation, and still a draft?
  meta_thread_id INTEGER,
  draft INTEGER NOT NULL DEFAULT 0,

  created_at TEXT NOT NULL DEFAULT ${NOW}
);

CREATE TABLE IF NOT EXISTS order_items (
  id SERIAL PRIMARY KEY,
  order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product TEXT NOT NULL,
  variant TEXT DEFAULT '',
  color TEXT DEFAULT '',
  size TEXT DEFAULT '',
  quantity INTEGER NOT NULL DEFAULT 1,
  unit_price DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS extractions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  result TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT ${NOW}
);

CREATE TABLE IF NOT EXISTS meta_oauth_states (
  state TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at BIGINT NOT NULL
);

-- One row per connected Facebook Page or Instagram account.
-- account_id = Page id (facebook) or Instagram business account id (instagram).
CREATE TABLE IF NOT EXISTS meta_connections (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  platform TEXT NOT NULL CHECK (platform IN ('facebook', 'instagram')),
  account_id TEXT NOT NULL,
  page_id TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  token_enc TEXT NOT NULL,
  fb_user_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT ${NOW},
  UNIQUE (platform, account_id)
);

-- One row per customer conversation, with where the automatic order detection stands:
--   auto_status   '' | draft | awaiting_confirm | needs_review | order_created | not_order
--   order_cutoff  last customer message already used for an order (the next order starts after it)
CREATE TABLE IF NOT EXISTS meta_threads (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  connection_id INTEGER NOT NULL REFERENCES meta_connections(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL,
  customer_name TEXT NOT NULL DEFAULT '',
  last_message TEXT NOT NULL DEFAULT '',
  last_message_at TEXT NOT NULL DEFAULT ${NOW},
  last_inbound_at BIGINT NOT NULL DEFAULT 0,
  unread INTEGER NOT NULL DEFAULT 0,
  auto_status TEXT NOT NULL DEFAULT '',
  auto_note TEXT NOT NULL DEFAULT '',
  order_id INTEGER,
  order_cutoff INTEGER NOT NULL DEFAULT 0,
  last_auto_reply TEXT NOT NULL DEFAULT '',
  draft_fields TEXT NOT NULL DEFAULT '',
  draft_items TEXT NOT NULL DEFAULT '',
  last_result TEXT NOT NULL DEFAULT '',
  analyzed_upto INTEGER NOT NULL DEFAULT 0,
  reply_error TEXT NOT NULL DEFAULT '',
  UNIQUE (connection_id, customer_id)
);

CREATE TABLE IF NOT EXISTS meta_messages (
  id SERIAL PRIMARY KEY,
  thread_id INTEGER NOT NULL REFERENCES meta_threads(id) ON DELETE CASCADE,
  mid TEXT NOT NULL,
  direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
  text TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT ${NOW},
  UNIQUE (thread_id, mid)
);

CREATE TABLE IF NOT EXISTS meta_deletions (
  code TEXT PRIMARY KEY,
  fb_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT ${NOW}
);

CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_orders_phone ON orders(user_id, phone);
CREATE INDEX IF NOT EXISTS idx_orders_meta_thread ON orders(meta_thread_id);
CREATE INDEX IF NOT EXISTS idx_items_order ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_products_user ON products(user_id);
CREATE INDEX IF NOT EXISTS idx_extractions_user ON extractions(user_id, id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_meta_conn_user ON meta_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_meta_conn_fbuser ON meta_connections(fb_user_id);
CREATE INDEX IF NOT EXISTS idx_meta_threads_user ON meta_threads(user_id, last_message_at);
CREATE INDEX IF NOT EXISTS idx_meta_msgs_thread ON meta_messages(thread_id, id);
`);

await db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(Date.now());
