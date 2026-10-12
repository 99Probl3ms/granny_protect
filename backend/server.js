// Node entry point for the backend (local development, or any Node host).
//
//   TYPESAFE_API_KEY=... node backend/server.js
//
// Environment:
//   TYPESAFE_API_KEY    TypeSafe key: calls Jev directly (preferred)
//   OPENROUTER_API_KEY  or an OpenRouter key: calls Jev through OpenRouter
//   JEV_API_URL         override the provider's endpoint
//   JEV_MODEL           override the pinned model (jev-1.13.0 / typesafe/jev-1.13)
//   TIER3_DISABLED=1  kill switch: /classify answers 503 and the extension falls back to heuristics
//   RATE_PER_MINUTE   per-install request limit (default 60)
//   DECISION_LOG      file to append decision log lines to (JSON lines); default stdout
//   PORT              default 8787

import http from 'node:http';
import fs from 'node:fs';
import { createHandler } from './src/handler.js';
import { createJevModel, jevConfigFromEnv } from './src/jev.js';

const env = process.env;
const disabled = env.TIER3_DISABLED === '1';
const jev = disabled ? null : jevConfigFromEnv(env);
const model = jev ? createJevModel(jev) : null;
if (!model && !disabled) console.warn('No TYPESAFE_API_KEY or OPENROUTER_API_KEY: Tier 3 is off (/classify answers 503).');

const logStream = env.DECISION_LOG ? fs.createWriteStream(env.DECISION_LOG, { flags: 'a' }) : process.stdout;
const handle = createHandler({
  model,
  disabled,
  ratePerMinute: Number(env.RATE_PER_MINUTE) || 60,
  log: (entry) => logStream.write(`${JSON.stringify(entry)}\n`),
});

function pick(headers, names) {
  return Object.fromEntries(names.filter((n) => headers[n] != null).map((n) => [n, headers[n]]));
}

const server = http.createServer(async (req, res) => {
  try {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = chunks.length ? Buffer.concat(chunks) : undefined;
    const request = new Request(`http://${req.headers.host || 'localhost'}${req.url}`, {
      method: req.method,
      headers: pick(req.headers, ['content-type', 'content-length', 'x-install-id']),
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : body,
    });
    const response = await handle(request);
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (err) {
    console.error(err);
    res.writeHead(500).end();
  }
});

const port = Number(env.PORT) || 8787;
server.listen(port, () => console.error(`granny_protect backend on http://localhost:${port} (tier3 ${jev ? `on: ${jev.provider} ${jev.model}` : 'off'})`));
