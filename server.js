import express from "express";
import cors from "cors";
import { z } from "zod";
import path from "node:path";
import { fileURLToPath } from "node:url";
import "dotenv/config";

import { db, isUniqueViolation } from "./db.js";
import { authRouter, requireAuth } from "./auth.js";
import { adminRouter, requireAdmin } from "./admin.js";
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
  aliases: z.string().trim().max(300).optional().default(""),
  // Options the customer must choose from, e.g. "noir, blanc" / "S, M, L". Empty = the product has none.
  // Left out of a request = unchanged (older screens that do not send them keep working).
  colors: z.string().trim().max(200).optional(),
  sizes: z.string().trim().max(200).optional()
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

// "N minutes ago" as the same text format the created_at columns use (UTC, YYYY-MM-DD HH:MM:SS).
const MINUTES_AGO = minutes =>
  `to_char((now() at time zone 'utc') - interval '${Number(minutes)} minutes', 'YYYY-MM-DD HH24:MI:SS')`;

const riskLevel = failed => (failed >= 2 ? "high" : failed === 1 ? "medium" : "low");

async function enrichMany(rows, uid) {
  if (!rows.length) return [];

  const ids = rows.map(row => row.id);
  const marks = ids.map(() => "?").join(",");

  const itemsByOrder = new Map();
  for (const item of await db.prepare(
    `SELECT * FROM order_items WHERE order_id IN (${marks}) ORDER BY id ASC`
  ).all(...ids)) {
    if (!itemsByOrder.has(item.order_id)) itemsByOrder.set(item.order_id, []);
    itemsByOrder.get(item.order_id).push(item);
  }

  // Risk only counts THIS user's orders: other sellers' data is never mixed in.
  const failedByPhone = new Map(
    (await db.prepare(`
      SELECT phone, COUNT(*) AS n FROM orders
      WHERE user_id = ? AND status IN ('returned', 'cancelled') GROUP BY phone
    `).all(uid)).map(row => [row.phone, row.n])
  );

  return rows.map(row => {
    const items = itemsByOrder.get(row.id) || [];
    const total = items.length
      ? items.reduce((sum, item) => sum + item.quantity * item.unit_price, 0)
      : row.quantity * row.unit_price;

    return { ...row, items, total, risk_level: riskLevel(failedByPhone.get(row.phone) || 0) };
  });
}

async function getOrder(id, uid) {
  const row = await db.prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?").get(id, uid);
  return row ? (await enrichMany([row], uid))[0] : null;
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

const createOrderTransaction = db.transaction(async (uid, data, items) => {
  const result = await insertOrderStatement.run({
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

  for (const item of items) await insertItemStatement.run({ order_id: orderId, ...item });

  return orderId;
});

// Same phone + same products + same quantity within 15 minutes = probably a double click.
async function findDuplicate(uid, phone, items) {
  const summary = summarizeItems(items);

  return await db.prepare(`
    SELECT id FROM orders
    WHERE user_id = ? AND phone = ? AND product = ? AND quantity = ?
      AND status != 'cancelled'
      AND created_at >= ${MINUTES_AGO(15)}
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

// What an order still needs from the customer. Used by the automation AND by the "Confirm" check,
// so both always agree. Address and size/color are required unless switched off with
// META_AUTO_REQUIRE_ADDRESS=0 / META_AUTO_REQUIRE_VARIANT=0.
const autoRequirements = () => ({
  requireAddress: process.env.META_AUTO_REQUIRE_ADDRESS !== "0",
  requireVariant: process.env.META_AUTO_REQUIRE_VARIANT !== "0"
});

const MISSING_NAMES = { customer_name: "name", phone: "phone", city: "city", address: "address" };

const splitOptions = value => String(value || "").split(/[,;\n،|]+/).map(option => option.trim()).filter(Boolean);

// Color / size are only asked for products that HAVE colors / sizes in the catalog (Products page).
// Each ask carries the available choices so the reply can list them.
async function orderMissing(uid, row, orderItems, { requireAddress = true, requireVariant = true, fallbackName = "" } = {}) {
  const missing = [];

  if (!(row.customer_name || fallbackName)) missing.push("customer_name");
  if (!row.phone) missing.push("phone");
  if (!row.city) missing.push("city");
  if (requireAddress && !row.address) missing.push("address");

  const variantAsks = [];
  const seen = new Set();

  if (requireVariant) {
    for (const item of orderItems) {
      const catalog = await db.prepare("SELECT colors, sizes FROM products WHERE user_id = ? AND name = ?")
        .get(uid, item.product);

      const colors = splitOptions(catalog?.colors);
      const sizes = splitOptions(catalog?.sizes);

      if (!colors.length && !sizes.length) continue; // this product needs nothing

      // A variant like "noir / M" written as one text counts as color + size.
      const parts = String(item.variant || "").split("/").map(part => part.trim()).filter(Boolean);
      let color = item.color || "";
      let size = item.size || "";

      if (!color && !size && parts.length) {
        if (colors.length && sizes.length) { color = parts[0]; size = parts[1] || ""; }
        else if (colors.length) color = parts[0];
        else size = parts[0];
      }

      for (const [kind, options, value] of [["color", colors, color], ["size", sizes, size]]) {
        const key = `${item.product}|${kind}`;
        if (options.length && !value && !seen.has(key)) {
          seen.add(key);
          variantAsks.push({ product: item.product, kind, options });
        }
      }
    }
  }

  if (variantAsks.length) missing.push("variant");

  return { missing, variantAsks };
}

// Applies what the AI understood from the customer's message to the item lines of a draft:
//   update = change a line (size, color, quantity, product), add = a new line, remove = delete a line.
// Lines are numbered from 1 in the order they were created (same numbering the AI was shown).
async function applyLineChanges(orderId, changes) {
  let applied = 0;

  for (const change of changes.slice(0, 10)) {
    const lines = await db.prepare("SELECT * FROM order_items WHERE order_id = ? ORDER BY id").all(orderId);

    if (change.action === "add") {
      const parsed = itemSchema.safeParse({
        product: change.product, quantity: change.quantity || 1,
        color: change.color || "", size: change.size || "", unit_price: change.unit_price || 0
      });
      if (!parsed.success) continue;
      await insertItemStatement.run({ order_id: orderId, ...prepareItems([parsed.data])[0] });
      applied++;
      continue;
    }

    const line = lines[(change.line || 0) - 1];
    if (!line) continue;

    if (change.action === "remove") {
      if (lines.length > 1) { await db.prepare("DELETE FROM order_items WHERE id = ?").run(line.id); applied++; }
      continue;
    }

    // update: only the fields the customer gave
    const next = {
      product: change.product || line.product,
      quantity: change.quantity || line.quantity,
      color: change.color || line.color || "",
      size: change.size || line.size || "",
      unit_price: change.product && change.product !== line.product ? (change.unit_price || 0) : line.unit_price
    };
    const variant = [next.color, next.size].filter(Boolean).join(" / ");

    await db.prepare(`
      UPDATE order_items SET product = ?, quantity = ?, color = ?, size = ?, variant = ?, unit_price = ?
      WHERE id = ? AND order_id = ?
    `).run(next.product, next.quantity, next.color, next.size, variant, next.unit_price, line.id, orderId);
    applied++;
  }

  if (applied) {
    const all = await db.prepare("SELECT product, variant, quantity, unit_price FROM order_items WHERE order_id = ? ORDER BY id").all(orderId);
    await db.prepare("UPDATE orders SET product = @product, variant = @variant, quantity = @quantity, unit_price = @unit_price WHERE id = @id")
      .run({ ...summarizeItems(all), id: orderId });
  }

  return applied;
}

const pickValid = (schema, value) => {
  const parsed = schema.safeParse(value == null ? "" : String(value));
  return parsed.success ? parsed.data : "";
};

setAutoOrderHandler(async (uid, ctx) => {
  try {
    return await db.transaction(async () => {
      const tid = ctx.threadId;
      let row = null;
      let created = false;
      let itemsChanged = false;
      let fieldsChanged = false;

      if (ctx.openOrderId) {
        row = await db.prepare(`
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

        const id = await createOrderTransaction(uid, {
          ...clean,
          status: "pending",
          delivery_status: "not_sent",
          cod_status: "not_received",
          source: ctx.source,
          message: String(ctx.message || "").slice(0, 4000)
        }, items);

        await db.prepare("UPDATE orders SET meta_thread_id = ?, draft = 1 WHERE id = ? AND user_id = ?").run(tid, id, uid);

        row = await db.prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?").get(id, uid);
        created = true;
      } else {
        // ---- later messages: fill what is still empty, nothing else
        const set = { message: String(ctx.message || "").slice(0, 4000) };

        for (const key of ["customer_name", "phone", "city", "address"]) {
          // A follow-up message may CORRECT a detail ("wrong address, it is ..."): the AI only reads the new messages for it.
          // Only a value the automation wrote itself may be corrected: a detail the seller edited by hand is never touched.
          const mayOverwrite = ctx.autoFields && row[key] === (ctx.autoFields[key] ?? "");
          if (clean[key] && (!row[key] || (mayOverwrite && clean[key] !== row[key]))) set[key] = clean[key];
        }

        // keys come from the fixed list above, never from the customer, so this is safe.
        await db.prepare(`
          UPDATE orders SET ${Object.keys(set).map(k => `${k} = @${k}`).join(", ")}
          WHERE id = @id AND user_id = @uid AND meta_thread_id = @tid AND draft = 1
        `).run({ ...set, id: row.id, uid, tid });

        // The AI's line operations (change a size, add a piece, remove a line) apply only while the seller has not edited the items.
        if (ctx.changes?.length && ctx.replaceItems) {
          itemsChanged = (await applyLineChanges(row.id, ctx.changes)) > 0;
        }
        fieldsChanged = Object.keys(set).some(key => key !== "message");

        // Items follow the customer only while the seller has not changed them.
        if (ctx.replaceItems && items.length) {
          await db.prepare(`
            UPDATE orders SET product = @product, variant = @variant, quantity = @quantity, unit_price = @unit_price
            WHERE id = @id AND user_id = @uid AND meta_thread_id = @tid AND draft = 1
          `).run({ ...summarizeItems(items), id: row.id, uid, tid });

          await db.prepare("DELETE FROM order_items WHERE order_id = ?").run(row.id);
          for (const item of items) await insertItemStatement.run({ order_id: row.id, ...item });
        }

        row = await db.prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?").get(row.id, uid);
      }

      // ---- what is still missing, and is the order complete?
      const name = row.customer_name || ctx.fallbackName || "";

      const orderItems = await db.prepare(
        "SELECT product, variant, color, size, unit_price FROM order_items WHERE order_id = ?"
      ).all(row.id);

      const { missing, variantAsks } = await orderMissing(uid, row, orderItems, {
        requireAddress: ctx.requireAddress,
        requireVariant: ctx.requireVariant,
        fallbackName: ctx.fallbackName
      });

      const unpriced = !orderItems.length || orderItems.some(item => !(item.unit_price > 0));

      let complete = false;
      let awaiting = false;
      let duplicate_id = null;

      if (!missing.length && ctx.canComplete && !unpriced) {
        const duplicate = await db.prepare(`
          SELECT id FROM orders
          WHERE user_id = ? AND id != ? AND phone = ? AND product = ? AND quantity = ?
            AND status != 'cancelled' AND created_at >= ${MINUTES_AGO(15)}
          ORDER BY id DESC LIMIT 1
        `).get(uid, row.id, row.phone, row.product, row.quantity);

        if (duplicate) {
          duplicate_id = duplicate.id; // the draft stays open: the seller decides
        } else if (ctx.requireApproval && !(ctx.approved && !itemsChanged && !fieldsChanged)) {
          awaiting = true; // everything is there: the customer must approve the summary first
          if (name && name !== row.customer_name) {
            await db.prepare("UPDATE orders SET customer_name = ? WHERE id = ? AND user_id = ? AND draft = 1").run(name, row.id, uid);
          }
        } else {
          await db.prepare(`
            UPDATE orders SET draft = 0, customer_name = ?
            WHERE id = ? AND user_id = ? AND meta_thread_id = ? AND draft = 1
          `).run(name, row.id, uid, tid);
          complete = true;
        }
      }

      return { ok: true, order_id: row.id, created, complete, awaiting, itemsChanged, fieldsChanged, missing, variantAsks, unpriced, duplicate_id };
    })();
  } catch (error) {
    console.error("Auto order save error:", error);
    return { ok: false, reason: "could not save" };
  }
});

// --------------------------------------------------
// ORDERS
// --------------------------------------------------

app.get("/api/orders", async (req, res) => {
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

  const rows = await db.prepare(`
    SELECT o.* FROM orders o
    WHERE ${where.join(" AND ")}
    ORDER BY o.created_at DESC, o.id DESC
    LIMIT ?
  `).all(...params, limit);

  res.json(await enrichMany(rows, uid));
});

app.post("/api/orders", async (req, res) => {
  const uid = req.user.id;
  const parsed = createSchema.safeParse(withLegacyItems(req.body));

  if (!parsed.success) return badRequest(res, parsed.error, "Invalid order");

  const data = parsed.data;
  const items = prepareItems(data.items);

  const forced = req.query.force === "1" || req.body?.force === true;
  const duplicate = forced ? null : await findDuplicate(uid, data.phone, items);

  if (duplicate) {
    return res.status(409).json({
      error: `Possible duplicate of order #${String(duplicate.id).padStart(4, "0")} (same phone and products in the last 15 minutes).`,
      duplicate_id: duplicate.id
    });
  }

  try {
    return res.status(201).json(await getOrder(await createOrderTransaction(uid, data, items), uid));
  } catch (error) {
    console.error("Create order error:", error);
    return res.status(500).json({ error: "Could not create order" });
  }
});

app.patch("/api/orders/:id", async (req, res) => {
  const uid = req.user.id;
  const id = parseId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid order ID" });

  if (!(await db.prepare("SELECT 1 FROM orders WHERE id = ? AND user_id = ?").get(id, uid))) {
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

  // An order still waiting for the customer cannot be confirmed (or sent) until it is complete.
  const current = await db.prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?").get(id, uid);

  if (current.draft === 1 && data.status && data.status !== "pending" && data.status !== "cancelled") {
    const shown = { ...current };
    for (const key of ["customer_name", "phone", "city", "address"]) if (data[key] !== undefined) shown[key] = data[key];

    const rows = items || await db.prepare("SELECT product, variant, color, size FROM order_items WHERE order_id = ?").all(id);
    const { missing, variantAsks } = await orderMissing(uid, shown, rows, autoRequirements());

    if (missing.length) {
      const waiting = [
        ...missing.filter(f => f !== "variant").map(f => MISSING_NAMES[f]),
        ...variantAsks.map(ask => `${ask.kind} of ${ask.product}`)
      ];

      return res.status(409).json({
        error: `This order is incomplete: still waiting for the customer (${waiting.join(", ")}).`
      });
    }

    data.draft = 0; // complete: the automation stops touching it
  }

  try {
    await db.transaction(async () => {
      if (items) {
        await db.prepare(`
          UPDATE orders
          SET product = @product, variant = @variant, quantity = @quantity, unit_price = @unit_price
          WHERE id = @id AND user_id = @uid
        `).run({ ...summarizeItems(items), id, uid });

        await db.prepare("DELETE FROM order_items WHERE order_id = ?").run(id);

        for (const item of items) await insertItemStatement.run({ order_id: id, ...item });
      }

      const keys = Object.keys(data);

      if (keys.length) {
        // keys come from the Zod schema above, never from the request, so this is safe.
        await db.prepare(`UPDATE orders SET ${keys.map(k => `${k} = @${k}`).join(", ")} WHERE id = @id AND user_id = @uid`)
          .run({ ...data, id, uid });
      }
    })();

    return res.json(await getOrder(id, uid));
  } catch (error) {
    console.error("Update order error:", error);
    return res.status(500).json({ error: "Could not update order" });
  }
});

app.delete("/api/orders/:id", async (req, res) => {
  const id = parseId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid order ID" });

  const result = await db.prepare("DELETE FROM orders WHERE id = ? AND user_id = ?").run(id, req.user.id);

  if (!result.changes) return res.status(404).json({ error: "Order not found" });

  res.json({ ok: true });
});

// --------------------------------------------------
// PRODUCTS (your catalog: names, prices, the words customers use)
// --------------------------------------------------

const isUniqueError = isUniqueViolation;

app.get("/api/products", async (req, res) => {
  res.json(
    await db.prepare("SELECT id, name, price, aliases, colors, sizes, created_at FROM products WHERE user_id = ? ORDER BY name")
      .all(req.user.id)
  );
});

app.post("/api/products", async (req, res) => {
  const uid = req.user.id;
  const parsed = productSchema.safeParse(req.body || {});

  if (!parsed.success) return badRequest(res, parsed.error, "Invalid product");

  try {
    const result = await db.prepare("INSERT INTO products (user_id, name, price, aliases, colors, sizes) VALUES (?, ?, ?, ?, ?, ?)")
      .run(uid, parsed.data.name, parsed.data.price, parsed.data.aliases, parsed.data.colors ?? "", parsed.data.sizes ?? "");

    return res.status(201).json(
      await db.prepare("SELECT id, name, price, aliases, colors, sizes, created_at FROM products WHERE id = ?").get(result.lastInsertRowid)
    );
  } catch (error) {
    if (isUniqueError(error)) return res.status(409).json({ error: "A product with this name already exists." });
    console.error("Create product error:", error);
    return res.status(500).json({ error: "Could not create product" });
  }
});

app.patch("/api/products/:id", async (req, res) => {
  const uid = req.user.id;
  const id = parseId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid product ID" });

  if (!(await db.prepare("SELECT 1 FROM products WHERE id = ? AND user_id = ?").get(id, uid))) {
    return res.status(404).json({ error: "Product not found" });
  }

  const parsed = productSchema.safeParse(req.body || {});

  if (!parsed.success) return badRequest(res, parsed.error, "Invalid product");

  try {
    await db.prepare("UPDATE products SET name = ?, price = ?, aliases = ?, colors = COALESCE(?::text, colors), sizes = COALESCE(?::text, sizes) WHERE id = ? AND user_id = ?")
      .run(parsed.data.name, parsed.data.price, parsed.data.aliases, parsed.data.colors ?? null, parsed.data.sizes ?? null, id, uid);

    return res.json(
      await db.prepare("SELECT id, name, price, aliases, colors, sizes, created_at FROM products WHERE id = ?").get(id)
    );
  } catch (error) {
    if (isUniqueError(error)) return res.status(409).json({ error: "A product with this name already exists." });
    console.error("Update product error:", error);
    return res.status(500).json({ error: "Could not update product" });
  }
});

app.delete("/api/products/:id", async (req, res) => {
  const id = parseId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid product ID" });

  const result = await db.prepare("DELETE FROM products WHERE id = ? AND user_id = ?").run(id, req.user.id);

  if (!result.changes) return res.status(404).json({ error: "Product not found" });

  res.json({ ok: true });
});

// --------------------------------------------------
// STATISTICS
// --------------------------------------------------

app.get("/api/stats", async (req, res) => {
  const uid = req.user.id;

  const count = async status =>
    (await db.prepare("SELECT COUNT(*) n FROM orders WHERE user_id = ? AND status = ?").get(uid, status)).n;

  const sumItems = async condition => (await db.prepare(`
    SELECT COALESCE(SUM(oi.quantity * oi.unit_price), 0) n
    FROM orders o JOIN order_items oi ON oi.order_id = o.id
    WHERE o.user_id = ? AND ${condition}
  `).get(uid)).n;

  res.json({
    total: (await db.prepare("SELECT COUNT(*) n FROM orders WHERE user_id = ?").get(uid)).n,
    pending: await count("pending"),
    confirmed: await count("confirmed"),
    delivered: await count("delivered"),
    returned: await count("returned"),
    revenue: await sumItems("o.status = 'delivered'"),
    codPending: await sumItems("o.cod_status = 'pending'")
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
    const products = await db.prepare("SELECT id, name, price, aliases FROM products WHERE user_id = ? ORDER BY name").all(uid);
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
    const saved = await db.prepare("INSERT INTO extractions (user_id, message, result) VALUES (?, ?, ?)")
      .run(uid, message, JSON.stringify(response));

    // Keep each account's history to the latest 200 messages.
    await db.prepare(`
      DELETE FROM extractions WHERE user_id = ? AND id NOT IN
        (SELECT id FROM extractions WHERE user_id = ? ORDER BY id DESC LIMIT 200)
    `).run(uid, uid);

    return res.json({ ...response, extraction_id: Number(saved.lastInsertRowid) });
  } catch (error) {
    console.error("Extraction error:", error.message);
    return res.status(502).json({ error: "AI analysis failed. Try again in a moment." });
  }
});

app.get("/api/extractions", async (req, res) => {
  const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));

  const rows = await db.prepare(
    "SELECT id, message, result, created_at FROM extractions WHERE user_id = ? ORDER BY id DESC LIMIT ?"
  ).all(req.user.id, limit);

  res.json(rows.map(row => {
    let result = null;
    try { result = JSON.parse(row.result); } catch { /* damaged row: shown without a result */ }
    return { id: row.id, message: row.message, created_at: row.created_at, result };
  }));
});

app.delete("/api/extractions/:id", async (req, res) => {
  const id = parseId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid ID" });

  const result = await db.prepare("DELETE FROM extractions WHERE id = ? AND user_id = ?").run(id, req.user.id);

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
