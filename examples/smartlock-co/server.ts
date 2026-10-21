/**
 * "SmartLock Co": a tiny, ordinary MCP server for a smart lock. It knows
 * nothing about HomePulse or the guard: whoever calls unlock_door gets the
 * door unlocked. That is the point of the demo: the guard proxy protects it
 * without a single change here.
 *
 *   tsx examples/smartlock-co/server.ts [port]     (default 9000)
 */
import { randomUUID } from "node:crypto";
import type { Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

export type DoorId = "front" | "garage";

export function createSmartLockCo(log: (line: string) => void = (l) => console.log(l)) {
  const locks: Record<DoorId, "locked" | "unlocked"> = { front: "locked", garage: "locked" };
  /** Every call that reached this server, so a demo can show what the guard let through. */
  const calls: Array<{ tool: string; args: Record<string, unknown>; at: string }> = [];

  function build(): McpServer {
    const s = new McpServer({ name: "smartlock-co", version: "2.4.1" });
    s.registerTool(
      "get_lock_status",
      { title: "Lock status", description: "Whether each SmartLock Co door is locked.", inputSchema: {}, annotations: { readOnlyHint: true } },
      async () => {
        calls.push({ tool: "get_lock_status", args: {}, at: new Date().toISOString() });
        return { content: [{ type: "text", text: `front: ${locks.front}, garage: ${locks.garage}` }], structuredContent: { ...locks } };
      },
    );
    s.registerTool(
      "unlock_door",
      { title: "Unlock a door", description: "Unlock a SmartLock Co door.", inputSchema: { door_id: z.enum(["front", "garage"]) } },
      async ({ door_id }) => {
        calls.push({ tool: "unlock_door", args: { door_id }, at: new Date().toISOString() });
        locks[door_id] = "unlocked";
        log(`  [SmartLock Co] ${door_id} door UNLOCKED`);
        return { content: [{ type: "text", text: `The ${door_id} door is unlocked.` }], structuredContent: { door_id, state: "unlocked" } };
      },
    );
    s.registerTool(
      "lock_door",
      { title: "Lock a door", description: "Lock a SmartLock Co door.", inputSchema: { door_id: z.enum(["front", "garage"]) } },
      async ({ door_id }) => {
        calls.push({ tool: "lock_door", args: { door_id }, at: new Date().toISOString() });
        locks[door_id] = "locked";
        return { content: [{ type: "text", text: `The ${door_id} door is locked.` }], structuredContent: { door_id, state: "locked" } };
      },
    );
    return s;
  }

  const app = express();
  const sessions = new Map<string, StreamableHTTPServerTransport>();
  app.post("/mcp", express.json(), async (req, res) => {
    const sid = req.header("mcp-session-id");
    let t = sid ? sessions.get(sid) : undefined;
    if (!t) {
      if (sid || !isInitializeRequest(req.body)) return res.status(sid ? 404 : 400).json({ jsonrpc: "2.0", error: { code: -32000, message: "No session" }, id: null });
      t = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          sessions.set(id, t!);
        },
      });
      t.onclose = () => {
        if (t?.sessionId) sessions.delete(t.sessionId);
      };
      await build().connect(t);
    }
    await t.handleRequest(req, res, req.body);
  });
  const bySession = async (req: express.Request, res: express.Response) => {
    const t = sessions.get(req.header("mcp-session-id") ?? "");
    if (!t) return res.status(404).end();
    await t.handleRequest(req, res);
  };
  app.get("/mcp", bySession);
  app.delete("/mcp", bySession);

  let http: HttpServer | null = null;
  return {
    locks,
    calls,
    async listen(port = 9000): Promise<string> {
      http = await new Promise<HttpServer>((r) => {
        const s = app.listen(port, "127.0.0.1", () => r(s));
      });
      return `http://127.0.0.1:${(http.address() as AddressInfo).port}/mcp`;
    },
    async close() {
      for (const t of sessions.values()) await t.close().catch(() => {});
      if (http) {
        http.closeAllConnections();
        await new Promise<void>((r) => http!.close(() => r()));
      }
    },
  };
}

if (process.argv[1] && /smartlock-co[\\/]server\.(ts|js)$/.test(process.argv[1])) {
  const lock = createSmartLockCo();
  lock.listen(Number(process.argv[2] ?? 9000)).then((url) => console.log(`SmartLock Co MCP server on ${url}`));
}
