import { env } from "cloudflare:workers";
import { createExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index";

describe("admin worker routing", () => {
  it("serves a minimal public health response with hardened headers", async () => {
    const response = await worker.fetch(
      new Request("https://kundenleicht.at/mcp/admin/health"),
      env,
      createExecutionContext(),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      service: "kundenleicht-composio-admin",
      authentication: "oauth2",
    });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/u);
  });

  it("routes both OAuth discovery documents and rejects anonymous MCP access", async () => {
    const asMetadata = await worker.fetch(
      new Request(
        "https://kundenleicht.at/.well-known/oauth-authorization-server/mcp/admin",
      ),
      env,
      createExecutionContext(),
    );
    const resourceMetadata = await worker.fetch(
      new Request(
        "https://kundenleicht.at/.well-known/oauth-protected-resource/mcp/admin",
      ),
      env,
      createExecutionContext(),
    );
    const anonymous = await worker.fetch(
      new Request("https://kundenleicht.at/mcp/admin", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      }),
      env,
      createExecutionContext(),
    );

    expect(asMetadata.status).toBe(200);
    expect(resourceMetadata.status).toBe(200);
    expect(anonymous.status).toBe(401);
  });

  it("does not claim the existing W3C health path or unrelated URLs", async () => {
    const w3cPath = await worker.fetch(
      new Request("https://kundenleicht.at/mcp/health"),
      env,
      createExecutionContext(),
    );
    const unrelated = await worker.fetch(
      new Request("https://kundenleicht.at/anything"),
      env,
      createExecutionContext(),
    );

    expect(w3cPath.status).toBe(404);
    expect(unrelated.status).toBe(404);
  });

  it("rate-limits public client registration before it can write OAuth state", async () => {
    const deniedLimiter: RateLimit = {
      limit: () => Promise.resolve({ success: false }),
    };
    const testEnv: Cloudflare.Env = {
      OAUTH_KV: env.OAUTH_KV,
      COMPOSIO_API_KEY: env.COMPOSIO_API_KEY,
      GOOGLE_CLIENT_ID: env.GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET: env.GOOGLE_CLIENT_SECRET,
      OAUTH_RATE_LIMITER: deniedLimiter,
      DCR_RATE_LIMITER: deniedLimiter,
    };
    const response = await worker.fetch(
      new Request("https://kundenleicht.at/mcp/admin/oauth/register", {
        method: "POST",
        headers: {
          "cf-connecting-ip": "203.0.113.8",
          "content-type": "application/json",
        },
        body: "{}",
      }),
      testEnv,
      createExecutionContext(),
    );

    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("60");
    expect(await response.json()).toEqual({ error: "rate_limited" });
  });
});
