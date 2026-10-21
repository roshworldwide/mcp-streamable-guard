#!/usr/bin/env node
/**
 * mcp-streamable-guard proxy --upstream http://localhost:9000/mcp --policy policy.yaml [--port 8790] [--state .guard]
 * mcp-streamable-guard bell  --proxy http://127.0.0.1:8790 [--state .guard]
 *
 * Tokens come from GUARD_AGENT_TOKEN, GUARD_HOMEOWNER_TOKEN, GUARD_CAREGIVER_TOKEN
 * and GUARD_RING_HMAC_KEY; any that are missing are generated once into
 * <state>/tokens.json (readable only by you).
 */
import fs from "node:fs";
import path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { parseArgs } from "node:util";
import { createGuardProxy, loadPolicy, ringSignature } from "./proxy/index.js";

type Tokens = { agent: string; homeowner: string; caregiver: string; ring_hmac_key: string };

function tokens(stateDir: string): { tokens: Tokens; file: string } {
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const file = path.join(stateDir, "tokens.json");
  const saved = (fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : {}) as Partial<Tokens>;
  const gen = () => randomBytes(32).toString("hex");
  const t: Tokens = {
    agent: process.env.GUARD_AGENT_TOKEN || saved.agent || gen(),
    homeowner: process.env.GUARD_HOMEOWNER_TOKEN || saved.homeowner || gen(),
    caregiver: process.env.GUARD_CAREGIVER_TOKEN || saved.caregiver || gen(),
    ring_hmac_key: process.env.GUARD_RING_HMAC_KEY || saved.ring_hmac_key || gen(),
  };
  fs.writeFileSync(file, JSON.stringify(t, null, 2), { mode: 0o600 });
  return { tokens: t, file };
}

function usage(code = 1): never {
  console.error(`Usage:
  mcp-streamable-guard proxy --upstream <url> --policy <policy.yaml> [--port 8790] [--host 127.0.0.1] [--state .guard]
                             [--upstream-header "Authorization: Bearer ..."] [--allowed-host name] [--allowed-origin url]
  mcp-streamable-guard bell  --proxy <http://127.0.0.1:8790> [--state .guard]`);
  process.exit(code);
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === "--help" || cmd === "-h") usage(cmd ? 0 : 1);
  const { values } = parseArgs({
    args: rest,
    options: {
      upstream: { type: "string" },
      policy: { type: "string" },
      port: { type: "string", default: "8790" },
      host: { type: "string", default: "127.0.0.1" },
      state: { type: "string", default: ".guard" },
      proxy: { type: "string" },
      "upstream-header": { type: "string", multiple: true },
      "allowed-host": { type: "string", multiple: true },
      "allowed-origin": { type: "string", multiple: true },
    },
  });
  const stateDir = path.resolve(values.state!);

  if (cmd === "bell") {
    const base = (values.proxy ?? "http://127.0.0.1:8790").replace(/\/mcp\/?$/, "").replace(/\/$/, "");
    const { tokens: t } = tokens(stateDir);
    const at = new Date().toISOString();
    const body = JSON.stringify({ meta: { version: "1.1", request_id: randomUUID(), timestamp: at }, data: { id: `evt_${randomUUID().slice(0, 12)}`, type: "button_press", attributes: { occurred_at: at } } });
    const r = await fetch(`${base}/ring/webhook`, { method: "POST", headers: { "Content-Type": "application/json", "X-Signature": ringSignature(body, t.ring_hmac_key) }, body });
    console.log(`Doorbell pressed (signed, Ring webhook format): ${r.status}`);
    return;
  }
  if (cmd !== "proxy") usage();
  if (!values.upstream || !values.policy) usage();

  const policy = loadPolicy(values.policy);
  const { tokens: t, file } = tokens(stateDir);
  const headers: Record<string, string> = {};
  for (const h of values["upstream-header"] ?? []) {
    const i = h.indexOf(":");
    if (i > 0) headers[h.slice(0, i).trim()] = h.slice(i + 1).trim();
  }
  const proxy = createGuardProxy({
    upstreamUrl: values.upstream,
    upstreamHeaders: headers,
    policy,
    tokens: { agent: t.agent, homeowner: t.homeowner, caregiver: t.caregiver },
    ringHmacKey: t.ring_hmac_key,
    stateDir,
    host: values.host,
    allowedHosts: values["allowed-host"],
    allowedOrigins: values["allowed-origin"],
    log: (l) => console.error(`[guard] ${l}`),
  });
  const url = await proxy.listen(Number(values.port));
  console.log(`mcp-streamable-guard proxy on ${url}`);
  console.log(`  upstream: ${values.upstream}`);
  console.log(`  guarded (physical): ${Object.keys(policy.physical).join(", ")}; everything else passes through`);
  console.log(`  tokens (agent, homeowner, caregiver) and the doorbell key: ${file}`);
  console.log(`  doorbell webhook: POST ${url.replace(/\/mcp$/, "")}/ring/webhook (X-Signature: sha256=<hex HMAC>)`);
  const stop = async () => {
    await proxy.close();
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

main().catch((err) => {
  console.error(String(err instanceof Error ? err.message : err));
  process.exit(1);
});
