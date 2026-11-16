// Shared by the test files: a fake Groq server and small HTTP helpers.
import http from "node:http";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";

export function tempDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "orders-"));
  process.env.DB_PATH = path.join(dir, "t.db");
  return process.env.DB_PATH;
}

export async function fakeGroq() {
  const state = { reply: {}, status: 200 };
  const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.writeHead(state.status, { "content-type": "application/json" });
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify(state.reply) } }] }));
    });
  });
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  process.env.GROQ_API_KEY = "test";
  process.env.AI_TIMEOUT_MS = "3000";
  process.env.GROQ_URL = `http://127.0.0.1:${server.address().port}/chat`;
  return { state, server };
}

export async function listen(app) {
  const server = http.createServer(app);
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;

  const call = (method, p, body, token) => fetch(base + p, {
    method,
    headers: { "content-type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body)
  }).then(async r => ({ status: r.status, body: await r.json().catch(() => ({})) }));

  return { server, base, call };
}
