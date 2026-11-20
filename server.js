import express from "express";
import cors from "cors";
import { z } from "zod";
import path from "node:path";
import { fileURLToPath } from "node:url";
import "dotenv/config";

import { db } from "./db.js";
import { authRouter, requireAuth } from "./auth.js";
import { analyzeMessage } from "./ai.js";
import { metaPublicRouter, metaRouter, setAutoOrderHandler } from "./meta.js";
import { normalizePhone, isValidTnPhone } from "./tunisia.js";
import { badRequest, parseId, rateLimit } from "./util.js";

// --------------------------------------------------
// SETTINGS
// --------------------------------------------------

const HOST = process.env.RENDER ? "0.0.0.0" : (process.env.HOST || "0.0.0.0");
const PORT = Number(process.env.PORT || 4000);
const MAX_QTY = 100;
const MAX_MESSAGE_CHARS = 2000;

// --------------------------------------------------
// EXPRESS
// --------------------------------------------------

const app = express();

if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);

const allowedOrigins = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  ...String(process.env.FRONTEND_ORIGIN || "").split(",").map(s => s.trim())
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked origin: ${origin}`));
  }
}));

// Meta webhook + OAuth callback: public, and the webhook needs the RAW body, so it goes BEFORE express.json().
app.use("/api/meta", metaPublicRouter);

app.use(express.json({ limit: "100kb" }));

// --------------------------------------------------
// PUBLIC ROUTES
// --------------------------------------------------

app.get("/api/health", (_, res) => res.json({ ok: true, app: "Orders API" }));

app.use("/api/auth", authRouter);

// Everything below needs a logged-in user. req.user.id is the owner of all data.
app.use("/api", requireAuth);

// Connect Facebook / Instagram, read and answer customer messages.
app.use("/api/meta", metaRouter);

const extractLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  keyFn: req => `u${req.user.id}`
});

// --------------------------------------------------
// VALIDATION
// --------------------------------------------------

const SOURCES = ["manual", "Facebook", "Instagram", "WhatsApp"];

const phoneSchema = z
  .string()
  .trim()
  .min(1, "Phone is required")
  .transform(normalizePhone)
  .refine(isValidTnPhone, "Phone must be a valid Tunisian number (8 digits, e.g. 22 123 456)");

const itemSchema = z.object({
  product: z.string().trim().min(1, "Product name is required").max(80),
  variant: z.string().trim().max(80).optional().default(""),
  color: z.string().trim().max(40).optional().default(""),
  size: z.string().trim().max(40).optional().default(""),
  quantity: z.coerce.number().int("Quantity must be a whole number").min(1, "Quantity must be at least 1").max(MAX_QTY),
  unit_price: z.coerce.number().min(0, "Price cannot be negative").max(100000)
});

const fields = {
  customer_name: z.string().trim().min(1, "Customer name is required").max(100),
  phone: phoneSchema,
  city: z.string().trim().min(1, "City is required").max(60),
  address: z.string().trim().max(300),
  items: z.array(itemSchema).min(1, "Add at least one product").max(20),
  status: z.enum(["pending", "confirmed", "cancelled", "delivered", "returned"]),
  delivery_status: z.enum(["not_sent", "prepared", "in_transit", "delivered", "returned"]),
  cod_status: z.enum(["not_received", "pending", "received", "refunded"]),
  source: z.enum(SOURCES),
  message: z.string().max(4000)
};

const createSchema = z.object({
  ...fields,
  address: fields.address.default(""),
  status: fields.status.default("pending"),
  delivery_status: fields.delivery_status.default("not_sent"),
  cod_status: fields.cod_status.default("not_received"),
  source: fields.source.default("manual"),
  message: fields.message.default("")
});

// Every field optional, and NO defaults: a PATCH must never reset what it does not mention.
const patchSchema = z.object(
  Object.fromEntries(Object.entries(fields).map(([key, schema]) => [key, schema.optional()]))
);

const productSchema = z.object({
  name: z.string().trim().min(1, "Product name is required").max(80),
  price: z.coerce.number().min(0, "Price cannot be negative").max(100000),
  aliases: z.string().trim().max(300).optional().default("")
});

// Older clients may send one product as flat fields.
function withLegacyItems(body) {
  if (!body || Array.isArray(body.items) || !body.product) return body;

  return {
    ...body,
    items: [{
      product: body.product,
      variant: body.variant || "",
      quantity: body.quantity || 1,
      unit_price: body.unit_price || 0
    }]
  };
}

// --------------------------------------------------
// ORDER HELPERS (every function takes the owner's id)
// --------------------------------------------------

function prepareItems(items) {
  return items.map(item => ({
    product: item.product,
    variant: item.variant || [item.color, item.size].filter(Boolean).join(" / "),
    color: item.color || "",
    size: item.size || "",
    quantity: item.quantity,
    unit_price: item.unit_price
  }));
}

function summarizeItems(items) {
  const quantity = items.reduce((sum, item) => sum + item.quantity, 0);
  const total = items.reduce((sum, item) => sum + item.quantity * item.unit_price, 0);

  return {
    product: items.map(item => item.product).join(", "),
    variant: items.map(item => item.variant).filter(Boolean).join(", "),
    quantity,
    unit_price: quantity > 0 ? total / quantity : 0
  };
}

const riskLevel = failed => (failed >= 2 ? "high" : failed === 1 ? "medium" : "low");

function enrichMany(rows, uid) {
  if (!rows.length) return [];

  const ids = rows.map(row => row.id);
  const marks = ids.map(() => "?").join(",");

  const itemsByOrder = new Map();
  for (const item of db.prepare(
    `SELECT * FROM order_items WHERE order_id IN (${marks}) ORDER BY id ASC`
  ).all(...ids)) {
    if (!itemsByOrder.has(item.order_id)) itemsByOrder.set(item.order_id, []);
    itemsByOrder.get(item.order_id).push(item);
  }

  // Risk only counts THIS user's orders: other sellers' data is never mixed in.
  const failedByPhone = new Map(
    db.prepare(`
      SELECT phone, COUNT(*) AS n FROM orders
      WHERE user_id = ? AND status IN ('returned', 'cancelled') GROUP BY phone
    `).all(uid).map(row => [row.phone, row.n])
  );

  return rows.map(row => {
    const items = itemsByOrder.get(row.id) || [];
    const total = items.length
      ? items.reduce((sum, item) => sum + item.quantity * item.unit_price, 0)
      : row.quantity * row.unit_price;

    return { ...row, items, total, risk_level: riskLevel(failedByPhone.get(row.phone) || 0) };
  });
}

function getOrder(id, uid) {
  const row = db.prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?").get(id, uid);
  return row ? enrichMany([row], uid)[0] : null;
}

const insertOrderStatement = db.prepare(`
  INSERT INTO orders (user_id, customer_name, phone, city, address, product, variant, quantity, unit_price,
                      status, delivery_status, cod_status, source, message)
  VALUES (@user_id, @customer_name, @phone, @city, @address, @product, @variant, @quantity, @unit_price,
          @status, @delivery_status, @cod_status, @source, @message)
`);

const insertItemStatement = db.prepare(`
  INSERT INTO order_items (order_id, product, variant, color, size, quantity, unit_price)
  VALUES (@order_id, @product, @variant, @color, @size, @quantity, @unit_price)
`);

const createOrderTransaction = db.transaction((uid, data, items) => {
  const result = insertOrderStatement.run({
    user_id: uid,
    customer_name: data.customer_name,
    phone: data.phone,
    city: data.city,
    address: data.address,
    ...summarizeItems(items),
    status: data.status,
    delivery_status: data.delivery_status,
    cod_status: data.cod_status,
    source: data.source,
    message: data.message
  });

  const orderId = Number(result.lastInsertRowid);

  for (const item of items) insertItemStatement.run({ order_id: orderId, ...item });

  return orderId;
});

// Same phone + same products + same quantity within 15 minutes = probably a double click.
function findDuplicate(uid, phone, items) {
  const summary = summarizeItems(items);

  return db.prepare(`
    SELECT id FROM orders
    WHERE user_id = ? AND phone = ? AND product = ? AND quantity = ?
      AND status != 'cancelled'
      AND created_at >= datetime('now', '-15 minutes')
    ORDER BY id DESC LIMIT 1
  `).get(uid, phone, summary.product, summary.quantity);
}

// --------------------------------------------------
// ORDERS BUILT FROM FACEBOOK / INSTAGRAM CONVERSATIONS (see meta.js)
//
// One order per conversation is "open" (draft = 1) until the customer has given everything.
// Only that order, identified by BOTH its id and the conversation that owns it (meta_thread_id),
// can be changed. Fields are validated one by one with the same rules as a manual order, and a field that
// already has a value is never overwritten.
// --------------------------------------------------

const pickValid = (schema, value) => {
  const parsed = schema.safeParse(value == null ? "" : String(value));
  return parsed.success ? parsed.data : "";
};

setAutoOrderHandler((uid, ctx) => {
  try {
    return db.transaction(() => {
      const tid = ctx.threadId;
      let row = null;
      let created = false;

      if (ctx.openOrderId) {
        row = db.prepare(`
          SELECT * FROM orders
          WHERE id = ? AND user_id = ? AND meta_thread_id = ? AND draft = 1 AND status = 'pending'
        `).get(ctx.openOrderId, uid, tid);

        if (!row) return { ok: false, gone: true };
      }

      const clean = {
        customer_name: pickValid(fields.customer_name, ctx.fields.customer_name),
        phone: pickValid(phoneSchema, ctx.fields.phone),
        city: pickValid(fields.city, ctx.fields.city),
        address: pickValid(fields.address, ctx.fields.address)
      };

      const items = prepareItems(
        (ctx.items || []).slice(0, 20).map(item => itemSchema.safeParse(item)).filter(r => r.success).map(r => r.data)
      );

      // ---- first message of an order: save the draft
      if (!row) {
        if (!items.length) return { ok: false, reason: "no valid product detected" };

        const id = createOrderTransaction(uid, {
          ...clean,
          status: "pending",
          delivery_status: "not_sent",
          cod_status: "not_received",
          source: ctx.source,
          message: String(ctx.message || "").slice(0, 4000)
        }, items);

        db.prepare("UPDATE orders SET meta_thread_id = ?, draft = 1 WHERE id = ? AND user_id = ?").run(tid, id, uid);

        row = db.prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?").get(id, uid);
        created = true;
      } else {
        // ---- later messages: fill what is still empty, nothing else
        const set = { message: String(ctx.message || "").slice(0, 4000) };

        for (const key of ["customer_name", "phone", "city", "address"]) {
          if (!row[key] && clean[key]) set[key] = clean[key];
        }

        // keys come from the fixed list above, never from the customer, so this is safe.
        db.prepare(`
          UPDATE orders SET ${Object.keys(set).map(k => `${k} = @${k}`).join(", ")}
          WHERE id = @id AND user_id = @uid AND meta_thread_id = @tid AND draft = 1
        `).run({ ...set, id: row.id, uid, tid });

        // Items follow the customer only while the seller has not changed them.
        if (ctx.replaceItems && items.length) {
          db.prepare(`
            UPDATE orders SET product = @product, variant = @variant, quantity = @quantity, unit_price = @unit_price
            WHERE id = @id AND user_id = @uid AND meta_thread_id = @tid AND draft = 1
          `).run({ ...summarizeItems(items), id: row.id, uid, tid });

          db.prepare("DELETE FROM order_items WHERE order_id = ?").run(row.id);
          for (const item of items) insertItemStatement.run({ order_id: row.id, ...item });
        }

        row = db.prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?").get(row.id, uid);
      }

      // ---- what is still missing, and is the order complete?
      const name = row.customer_name || ctx.fallbackName || "";
      const missing = [];
      if (!name) missing.push("customer_name");
      if (!row.phone) missing.push("phone");
      if (!row.city) missing.push("city");
      if (ctx.requireAddress && !row.address) missing.push("address");

      const orderItems = db.prepare("SELECT unit_price FROM order_items WHERE order_id = ?").all(row.id);
      const unpriced = !orderItems.length || orderItems.some(item => !(item.unit_price > 0));

      let complete = false;
      let duplicate_id = null;

      if (!missing.length && ctx.canComplete && !unpriced) {
        const duplicate = db.prepare(`
          SELECT id FROM orders
          WHERE user_id = ? AND id != ? AND phone = ? AND product = ? AND quantity = ?
            AND status != 'cancelled' AND created_at >= datetime('now', '-15 minutes')
          ORDER BY id DESC LIMIT 1
        `).get(uid, row.id, row.phone, row.product, row.quantity);

        if (duplicate) {
          duplicate_id = duplicate.id; // the draft stays open: the seller decides
        } else {
          db.prepare(`
            UPDATE orders SET draft = 0, customer_name = ?
            WHERE id = ? AND user_id = ? AND meta_thread_id = ? AND draft = 1
          `).run(name, row.id, uid, tid);
          complete = true;
        }
      }

      return { ok: true, order_id: row.id, created, complete, missing, unpriced, duplicate_id };
    })();
  } catch (error) {
    console.error("Auto order save error:", error);
    return { ok: false, reason: "could not save" };
  }
});

// --------------------------------------------------
// ORDERS
// --------------------------------------------------

app.get("/api/orders", (req, res) => {
  const uid = req.user.id;
  const q = String(req.query.q || "").trim().toLowerCase().slice(0, 100);
  const status = String(req.query.status || "");
  const limit = Math.min(1000, Math.max(1, Number(req.query.limit) || 300));

  const where = ["o.user_id = ?"];
  const params = [uid];

  if (status && status !== "all") {
    where.push("o.status = ?");
    params.push(status);
  }

  if (q) {
    const like = `%${q.replace(/[%_\\]/g, "\\$&")}%`;
    where.push(`(
      LOWER(o.customer_name) LIKE ? ESCAPE '\\'
      OR o.phone LIKE ? ESCAPE '\\'
      OR LOWER(o.city) LIKE ? ESCAPE '\\'
      OR EXISTS (SELECT 1 FROM order_items i
                 WHERE i.order_id = o.id AND LOWER(i.product) LIKE ? ESCAPE '\\')
    )`);
    params.push(like, like, like, like);
  }

  const rows = db.prepare(`
    SELECT o.* FROM orders o
    WHERE ${where.join(" AND ")}
    ORDER BY datetime(o.created_at) DESC, o.id DESC
    LIMIT ?
  `).all(...params, limit);

  res.json(enrichMany(rows, uid));
});

app.post("/api/orders", (req, res) => {
  const uid = req.user.id;
  const parsed = createSchema.safeParse(withLegacyItems(req.body));

  if (!parsed.success) return badRequest(res, parsed.error, "Invalid order");

  const data = parsed.data;
  const items = prepareItems(data.items);

  const forced = req.query.force === "1" || req.body?.force === true;
  const duplicate = forced ? null : findDuplicate(uid, data.phone, items);

  if (duplicate) {
    return res.status(409).json({
      error: `Possible duplicate of order #${String(duplicate.id).padStart(4, "0")} (same phone and products in the last 15 minutes).`,
      duplicate_id: duplicate.id
    });
  }

  try {
    return res.status(201).json(getOrder(createOrderTransaction(uid, data, items), uid));
  } catch (error) {
    console.error("Create order error:", error);
    return res.status(500).json({ error: "Could not create order" });
  }
});

app.patch("/api/orders/:id", (req, res) => {
  const uid = req.user.id;
  const id = parseId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid order ID" });

  if (!db.prepare("SELECT 1 FROM orders WHERE id = ? AND user_id = ?").get(id, uid)) {
    return res.status(404).json({ error: "Order not found" });
  }

  const parsed = patchSchema.safeParse(req.body || {});

  if (!parsed.success) return badRequest(res, parsed.error, "Invalid order data");

  // Only fields the client really sent (Zod leaves the others undefined).
  const { items: rawItems, ...rest } = parsed.data;
  const data = Object.fromEntries(Object.entries(rest).filter(([, value]) => value !== undefined));

  if (!Object.keys(data).length && !rawItems) {
    return res.status(400).json({ error: "No editable fields supplied" });
  }

  const items = rawItems ? prepareItems(rawItems) : null;

  try {
    db.transaction(() => {
      if (items) {
        db.prepare(`
          UPDATE orders
          SET product = @product, variant = @variant, quantity = @quantity, unit_price = @unit_price
          WHERE id = @id AND user_id = @uid
        `).run({ ...summarizeItems(items), id, uid });

        db.prepare("DELETE FROM order_items WHERE order_id = ?").run(id);

        for (const item of items) insertItemStatement.run({ order_id: id, ...item });
      }

      const keys = Object.keys(data);

      if (keys.length) {
        // keys come from the Zod schema above, never from the request, so this is safe.
        db.prepare(`UPDATE orders SET ${keys.map(k => `${k} = @${k}`).join(", ")} WHERE id = @id AND user_id = @uid`)
          .run({ ...data, id, uid });
      }
    })();

    return res.json(getOrder(id, uid));
  } catch (error) {
    console.error("Update order error:", error);
    return res.status(500).json({ error: "Could not update order" });
  }
});

app.delete("/api/orders/:id", (req, res) => {
  const id = parseId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid order ID" });

  const result = db.prepare("DELETE FROM orders WHERE id = ? AND user_id = ?").run(id, req.user.id);

  if (!result.changes) return res.status(404).json({ error: "Order not found" });

  res.json({ ok: true });
});

// --------------------------------------------------
// PRODUCTS (your catalog: names, prices, the words customers use)
// --------------------------------------------------

const isUniqueError = error => String(error.code).startsWith("SQLITE_CONSTRAINT");

app.get("/api/products", (req, res) => {
  res.json(
    db.prepare("SELECT id, name, price, aliases, created_at FROM products WHERE user_id = ? ORDER BY name COLLATE NOCASE")
      .all(req.user.id)
  );
});

app.post("/api/products", (req, res) => {
  const uid = req.user.id;
  const parsed = productSchema.safeParse(req.body || {});

  if (!parsed.success) return badRequest(res, parsed.error, "Invalid product");

  try {
    const result = db.prepare("INSERT INTO products (user_id, name, price, aliases) VALUES (?, ?, ?, ?)")
      .run(uid, parsed.data.name, parsed.data.price, parsed.data.aliases);

    return res.status(201).json(
      db.prepare("SELECT id, name, price, aliases, created_at FROM products WHERE id = ?").get(result.lastInsertRowid)
    );
  } catch (error) {
    if (isUniqueError(error)) return res.status(409).json({ error: "A product with this name already exists." });
    console.error("Create product error:", error);
    return res.status(500).json({ error: "Could not create product" });
  }
});

app.patch("/api/products/:id", (req, res) => {
  const uid = req.user.id;
  const id = parseId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid product ID" });

  if (!db.prepare("SELECT 1 FROM products WHERE id = ? AND user_id = ?").get(id, uid)) {
    return res.status(404).json({ error: "Product not found" });
  }

  const parsed = productSchema.safeParse(req.body || {});

  if (!parsed.success) return badRequest(res, parsed.error, "Invalid product");

  try {
    db.prepare("UPDATE products SET name = ?, price = ?, aliases = ? WHERE id = ? AND user_id = ?")
      .run(parsed.data.name, parsed.data.price, parsed.data.aliases, id, uid);

    return res.json(
      db.prepare("SELECT id, name, price, aliases, created_at FROM products WHERE id = ?").get(id)
    );
  } catch (error) {
    if (isUniqueError(error)) return res.status(409).json({ error: "A product with this name already exists." });
    console.error("Update product error:", error);
    return res.status(500).json({ error: "Could not update product" });
  }
});

app.delete("/api/products/:id", (req, res) => {
  const id = parseId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid product ID" });

  const result = db.prepare("DELETE FROM products WHERE id = ? AND user_id = ?").run(id, req.user.id);

  if (!result.changes) return res.status(404).json({ error: "Product not found" });

  res.json({ ok: true });
});

// --------------------------------------------------
// STATISTICS
// --------------------------------------------------

app.get("/api/stats", (req, res) => {
  const uid = req.user.id;

  const count = status =>
    db.prepare("SELECT COUNT(*) n FROM orders WHERE user_id = ? AND status = ?").get(uid, status).n;

  const sumItems = condition => db.prepare(`
    SELECT COALESCE(SUM(oi.quantity * oi.unit_price), 0) n
    FROM orders o JOIN order_items oi ON oi.order_id = o.id
    WHERE o.user_id = ? AND ${condition}
  `).get(uid).n;

  res.json({
    total: db.prepare("SELECT COUNT(*) n FROM orders WHERE user_id = ?").get(uid).n,
    pending: count("pending"),
    confirmed: count("confirmed"),
    delivered: count("delivered"),
    returned: count("returned"),
    revenue: sumItems("o.status = 'delivered'"),
    codPending: sumItems("o.cod_status = 'pending'")
  });
});

// --------------------------------------------------
// GROQ STATUS
// --------------------------------------------------

app.get("/api/ai/status", async (_, res) => {
  const apiKey = process.env.GROQ_API_KEY;
  const model = process.env.GROQ_MODEL || "openai/gpt-oss-20b";
  const base = { provider: "groq", model };

  if (!apiKey) {
    return res.json({ ...base, connected: false, modelAvailable: false, error: "GROQ_API_KEY is missing" });
  }

  try {
    const url = process.env.GROQ_MODELS_URL || "https://api.groq.com/openai/v1/models";
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(8000)
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      return res.json({
        ...base, connected: false, modelAvailable: false,
        error: data.error?.message || "Groq connection failed"
      });
    }

    return res.json({
      ...base,
      connected: true,
      modelAvailable: (data.data || []).some(item => item.id === model)
    });
  } catch (error) {
    return res.json({ ...base, connected: false, modelAvailable: false, error: error.message });
  }
});

// --------------------------------------------------
// AI EXTRACTION (+ history saved in the database)
// --------------------------------------------------

app.post("/api/extract", extractLimiter, async (req, res) => {
  const uid = req.user.id;
  const message = String(req.body?.message ?? "").trim();

  if (!message) return res.status(400).json({ error: "Message is required" });

  if (message.length > MAX_MESSAGE_CHARS) {
    return res.status(400).json({ error: `Message is too long (max ${MAX_MESSAGE_CHARS} characters).` });
  }

  try {
    const products = db.prepare("SELECT id, name, price, aliases FROM products WHERE user_id = ? ORDER BY name").all(uid);
    const result = await analyzeMessage(message, { products });

    const items = result.items || [];
    const quantity = items.reduce((total, item) => total + item.quantity, 0);
    const totalPrice = items.reduce((total, item) => total + item.quantity * (item.unit_price || 0), 0);

    const extracted = {
      customer_name: result.extracted.customer_name || "",
      phone: result.extracted.phone || "",
      city: result.extracted.city || "",
      address: result.extracted.address || "",
      product: items.map(item => item.product).join(", "),
      variant: items
        .map(item => [item.color, item.size, item.quantity > 1 ? `x${item.quantity}` : ""].filter(Boolean).join(" / "))
        .filter(Boolean)
        .join(", "),
      quantity,
      unit_price: quantity ? totalPrice / quantity : 0
    };

    const response = {
      source: result.provider,
      model: result.model,
      warning: result.provider === "rules"
        ? "AI was unavailable, so this draft comes from simple rules. Verify every field."
        : null,
      extracted,
      items,
      missing: result.missing,
      uncertain_fields: result.uncertain_fields,
      confidence: result.confidence,
      customer_intent: result.customer_intent,
      suggested_reply: result.suggested_reply,
      reply_derja: result.suggested_reply || "",
      reply_french: ""
    };

    // Saved, so the message and the AI's answer are still there after a refresh or on another device.
    const saved = db.prepare("INSERT INTO extractions (user_id, message, result) VALUES (?, ?, ?)")
      .run(uid, message, JSON.stringify(response));

    // Keep each account's history to the latest 200 messages.
    db.prepare(`
      DELETE FROM extractions WHERE user_id = ? AND id NOT IN
        (SELECT id FROM extractions WHERE user_id = ? ORDER BY id DESC LIMIT 200)
    `).run(uid, uid);

    return res.json({ ...response, extraction_id: Number(saved.lastInsertRowid) });
  } catch (error) {
    console.error("Extraction error:", error.message);
    return res.status(502).json({ error: "AI analysis failed. Try again in a moment." });
  }
});

app.get("/api/extractions", (req, res) => {
  const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));

  const rows = db.prepare(
    "SELECT id, message, result, created_at FROM extractions WHERE user_id = ? ORDER BY id DESC LIMIT ?"
  ).all(req.user.id, limit);

  res.json(rows.map(row => {
    let result = null;
    try { result = JSON.parse(row.result); } catch { /* damaged row: shown without a result */ }
    return { id: row.id, message: row.message, created_at: row.created_at, result };
  }));
});

app.delete("/api/extractions/:id", (req, res) => {
  const id = parseId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid ID" });

  const result = db.prepare("DELETE FROM extractions WHERE id = ? AND user_id = ?").run(id, req.user.id);

  if (!result.changes) return res.status(404).json({ error: "Not found" });

  res.json({ ok: true });
});

// --------------------------------------------------
// ERRORS (always JSON, never a stack trace)
// --------------------------------------------------

app.use((error, req, res, next) => {
  if (error?.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON" });
  if (error?.type === "entity.too.large") return res.status(413).json({ error: "Request too large" });
  if (String(error?.message).startsWith("CORS blocked")) return res.status(403).json({ error: "Origin not allowed" });

  console.error("Unhandled error:", error);
  res.status(500).json({ error: "Server error" });
});

// --------------------------------------------------
// START
// --------------------------------------------------

export { app, db };

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  app.listen(PORT, HOST, () => {
    console.log(`Orders API running on http://${HOST}:${PORT}`);
    if (HOST !== "127.0.0.1" && HOST !== "localhost") {
      console.log("Listening to the network: put the site behind HTTPS before real customers use it.");
    }
  });
}
