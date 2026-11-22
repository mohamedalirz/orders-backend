// Owner (admin) area, mounted at /api/admin.
// Owner = every email listed in the ADMIN_EMAILS environment variable (comma-separated).
// Never returns the clients' own customers, passwords, or tokens.

import express from "express";
import { db, pool } from "./db.js";
import { parseId } from "./util.js";

const adminEmails = () =>
  String(process.env.ADMIN_EMAILS || "")
    .split(",")
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);

export const isAdminEmail = email => adminEmails().includes(String(email || "").trim().toLowerCase());

export function requireAdmin(req, res, next) {
  if (!isAdminEmail(req.user?.email)) return res.status(403).json({ error: "Owner access only" });
  next();
}

const stamp = ms => new Date(ms).toISOString().slice(0, 19).replace("T", " ");
const daysAgo = n => stamp(Date.now() - n * 86_400_000);

function fillDays(rows, days) {
  const byDay = new Map(rows.map(r => [r.d, Number(r.n)]));
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86_400_000).toISOString().slice(0, 10);
    out.push({ date: d, count: byDay.get(d) || 0 });
  }
  return out;
}

const REVENUE_SQL = `
  SELECT COALESCE(SUM(oi.quantity * oi.unit_price), 0) n
  FROM orders o JOIN order_items oi ON oi.order_id = o.id
  WHERE o.draft = 0 AND o.status = 'delivered'`;

function health(row) {
  const last = [row.last_login_at, row.last_order_at, row.created_at].filter(Boolean).sort().pop() || "";
  if (last >= daysAgo(7)) return "active";
  if (last >= daysAgo(30)) return "idle";
  return "inactive";
}

const CLIENT_SQL = `
  SELECT
    u.id, u.email, u.name, u.store_name, u.created_at, u.last_login_at,
    (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id AND o.draft = 0) AS orders,
    (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id AND o.draft = 0 AND o.created_at >= ?) AS orders_30d,
    (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id AND o.draft = 0 AND o.status = 'pending') AS pending,
    (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id AND o.draft = 0 AND o.status = 'confirmed') AS confirmed,
    (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id AND o.draft = 0 AND o.status = 'delivered') AS delivered,
    (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id AND o.draft = 0 AND o.status = 'returned') AS returned,
    (SELECT MAX(o.created_at) FROM orders o WHERE o.user_id = u.id AND o.draft = 0) AS last_order_at,
    (SELECT COALESCE(SUM(oi.quantity * oi.unit_price), 0)
       FROM orders o JOIN order_items oi ON oi.order_id = o.id
       WHERE o.user_id = u.id AND o.draft = 0 AND o.status = 'delivered') AS revenue,
    (SELECT COUNT(*) FROM products p WHERE p.user_id = u.id) AS products,
    (SELECT COUNT(*) FROM extractions e WHERE e.user_id = u.id) AS ai_extractions,
    (SELECT COUNT(*) FROM meta_threads t WHERE t.user_id = u.id) AS conversations,
    (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id AND o.draft = 0 AND o.meta_thread_id IS NOT NULL) AS auto_orders,
    (SELECT COUNT(*) FROM meta_connections c WHERE c.user_id = u.id AND c.status = 'active') AS channels_active,
    (SELECT COUNT(*) FROM meta_connections c WHERE c.user_id = u.id AND c.status <> 'active') AS channels_broken,
    (SELECT string_agg(DISTINCT c.platform, ',') FROM meta_connections c WHERE c.user_id = u.id) AS platforms,
    (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > ?) AS devices
  FROM users u`;

function shapeClient(r) {
  return {
    id: r.id,
    email: r.email,
    name: r.name,
    store_name: r.store_name,
    created_at: r.created_at,
    last_login_at: r.last_login_at || "",
    last_order_at: r.last_order_at || "",
    health: health(r),
    orders: r.orders,
    orders_30d: r.orders_30d,
    pending: r.pending,
    confirmed: r.confirmed,
    delivered: r.delivered,
    returned: r.returned,
    revenue: r.revenue,
    products: r.products,
    ai_extractions: r.ai_extractions,
    conversations: r.conversations,
    auto_orders: r.auto_orders,
    channels_active: r.channels_active,
    channels_broken: r.channels_broken,
    platforms: r.platforms ? String(r.platforms).split(",") : [],
    devices: r.devices
  };
}

export const adminRouter = express.Router();

adminRouter.get("/summary", async (req, res) => {
  const d7 = daysAgo(7);
  const d30 = daysAgo(30);

  const one = async (sql, ...args) => (await db.prepare(sql).get(...args)).n;

  const [
    totalClients, new7, new30, totalOrders, orders7, orders30, revenue,
    withProducts, withChannel, withOrder, withFiveOrders,
    activeChannels, brokenChannels, extractions30, threads, autoOrders
  ] = await Promise.all([
    one("SELECT COUNT(*) n FROM users"),
    one("SELECT COUNT(*) n FROM users WHERE created_at >= ?", d7),
    one("SELECT COUNT(*) n FROM users WHERE created_at >= ?", d30),
    one("SELECT COUNT(*) n FROM orders WHERE draft = 0"),
    one("SELECT COUNT(*) n FROM orders WHERE draft = 0 AND created_at >= ?", d7),
    one("SELECT COUNT(*) n FROM orders WHERE draft = 0 AND created_at >= ?", d30),
    one(REVENUE_SQL),
    one("SELECT COUNT(DISTINCT user_id) n FROM products"),
    one("SELECT COUNT(DISTINCT user_id) n FROM meta_connections WHERE status = 'active'"),
    one("SELECT COUNT(DISTINCT user_id) n FROM orders WHERE draft = 0"),
    one("SELECT COUNT(*) n FROM (SELECT user_id FROM orders WHERE draft = 0 GROUP BY user_id HAVING COUNT(*) >= 5) t"),
    one("SELECT COUNT(*) n FROM meta_connections WHERE status = 'active'"),
    one("SELECT COUNT(*) n FROM meta_connections WHERE status <> 'active'"),
    one("SELECT COUNT(*) n FROM extractions WHERE created_at >= ?", d30),
    one("SELECT COUNT(*) n FROM meta_threads"),
    one("SELECT COUNT(*) n FROM orders WHERE draft = 0 AND meta_thread_id IS NOT NULL")
  ]);

  const rows = await db.prepare(`
    SELECT u.created_at, u.last_login_at,
      (SELECT MAX(o.created_at) FROM orders o WHERE o.user_id = u.id AND o.draft = 0) AS last_order_at
    FROM users u`).all();

  const clientHealth = { active: 0, idle: 0, inactive: 0 };
  for (const r of rows) clientHealth[health(r)] += 1;

  const [signupRows, orderRows, statusRows, sourceRows, topClients, newest] = await Promise.all([
    db.prepare("SELECT substr(created_at, 1, 10) d, COUNT(*) n FROM users WHERE created_at >= ? GROUP BY d").all(daysAgo(30)),
    db.prepare("SELECT substr(created_at, 1, 10) d, COUNT(*) n FROM orders WHERE draft = 0 AND created_at >= ? GROUP BY d").all(daysAgo(30)),
    db.prepare("SELECT status, COUNT(*) n FROM orders WHERE draft = 0 GROUP BY status").all(),
    db.prepare("SELECT source, COUNT(*) n FROM orders WHERE draft = 0 GROUP BY source ORDER BY n DESC").all(),
    db.prepare(`${CLIENT_SQL} ORDER BY orders_30d DESC, orders DESC LIMIT 5`).all(d30, Date.now()),
    db.prepare(`${CLIENT_SQL} ORDER BY u.id DESC LIMIT 5`).all(d30, Date.now())
  ]);

  const size = await db.prepare("SELECT pg_database_size(current_database()) n").get();

  res.json({
    generated_at: stamp(Date.now()),
    clients: { total: totalClients, new_7d: new7, new_30d: new30, health: clientHealth },
    funnel: [
      { key: "signed_up", label: "Signed up", count: totalClients },
      { key: "product", label: "Added a product", count: withProducts },
      { key: "channel", label: "Connected Facebook / Instagram", count: withChannel },
      { key: "order", label: "Received a first order", count: withOrder },
      { key: "regular", label: "5 orders or more", count: withFiveOrders }
    ],
    orders: {
      total: totalOrders,
      last_7d: orders7,
      last_30d: orders30,
      auto_created: autoOrders,
      revenue_delivered: revenue,
      by_status: Object.fromEntries(statusRows.map(r => [r.status, r.n])),
      by_source: sourceRows.map(r => ({ source: r.source, count: r.n }))
    },
    channels: { active: activeChannels, needing_reconnect: brokenChannels, conversations: threads },
    ai: { extractions_30d: extractions30 },
    series: { signups_30d: fillDays(signupRows, 30), orders_30d: fillDays(orderRows, 30) },
    top_clients: topClients.map(shapeClient),
    newest_clients: newest.map(shapeClient),
    system: {
      database_bytes: Number(size.n),
      database_limit_bytes: 512 * 1024 * 1024,
      uptime_seconds: Math.round(process.uptime()),
      node: process.version,
      db_pool: { total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount },
      config: {
        groq_key: Boolean(process.env.GROQ_API_KEY),
        meta_app: Boolean(process.env.META_APP_ID && process.env.META_APP_SECRET),
        meta_token_key: Boolean(process.env.META_TOKEN_KEY),
        meta_verify_token: Boolean(process.env.META_VERIFY_TOKEN),
        frontend_origin: Boolean(process.env.FRONTEND_ORIGIN),
        signups_open: process.env.ALLOW_SIGNUP !== "0",
        admin_emails: adminEmails().length
      }
    }
  });
});

adminRouter.get("/clients", async (req, res) => {
  const rows = await db.prepare(`${CLIENT_SQL} ORDER BY u.id DESC`).all(daysAgo(30), Date.now());
  res.json(rows.map(shapeClient));
});

adminRouter.get("/clients/:id", async (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid ID" });

  const row = await db.prepare(`${CLIENT_SQL} WHERE u.id = ?`).get(daysAgo(30), Date.now(), id);
  if (!row) return res.status(404).json({ error: "Client not found" });

  const [channels, products, recentOrders, perDay, byCity] = await Promise.all([
    db.prepare("SELECT platform, name, status, created_at FROM meta_connections WHERE user_id = ? ORDER BY id").all(id),
    db.prepare("SELECT name, price, colors, sizes FROM products WHERE user_id = ? ORDER BY name LIMIT 100").all(id),
    db.prepare(`SELECT o.id, o.status, o.source, o.created_at,
                  COALESCE((SELECT SUM(oi.quantity * oi.unit_price) FROM order_items oi WHERE oi.order_id = o.id), 0) AS total
                FROM orders o WHERE o.user_id = ? AND o.draft = 0 ORDER BY o.id DESC LIMIT 10`).all(id),
    db.prepare("SELECT substr(created_at, 1, 10) d, COUNT(*) n FROM orders WHERE user_id = ? AND draft = 0 AND created_at >= ? GROUP BY d").all(id, daysAgo(30)),
    db.prepare("SELECT city, COUNT(*) n FROM orders WHERE user_id = ? AND draft = 0 GROUP BY city ORDER BY n DESC LIMIT 5").all(id)
  ]);

  res.json({
    ...shapeClient(row),
    channels,
    catalog: products,
    recent_orders: recentOrders,
    orders_30d_series: fillDays(perDay, 30),
    top_cities: byCity.map(r => ({ city: r.city, count: r.n }))
  });
});
