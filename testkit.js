// Shared by the test files: a fake Groq server and small HTTP helpers.
import http from "node:http";
import pg from "pg";

// Every test file gets its own empty Postgres database.
// TEST_DATABASE_URL = a Postgres server you can create databases on (default: local, user postgres).
export async function tempDb() {
  const admin = process.env.TEST_DATABASE_URL || "postgresql://postgres@127.0.0.1:5432/postgres";
  const name = `t_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  const client = new pg.Client({ connectionString: admin });
  await client.connect();
  await client.query(`CREATE DATABASE ${name}`);
  await client.end();

  const url = new URL(admin);
  url.pathname = `/${name}`;
  process.env.DATABASE_URL = url.toString();
  return name;
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
