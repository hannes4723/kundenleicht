import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAdminResourceServer } from "../src/mcp";
import { MCP_RESOURCE, READ_SCOPE, createOAuthRouter } from "../src/oauth";

const ADMIN_CONTEXT = {
  props: {
    googleSub: "109876543210987654321",
    email: "hannes4723@gmail.com",
    emailVerified: true as const,
    role: "admin" as const,
  },
  audience: MCP_RESOURCE,
  expiresAt: Math.floor(Date.now() / 1_000) + 3_600,
  scope: [READ_SCOPE],
  userId: "google-109876543210987654321",
  clientId: "security-regression-client",
};

function authenticatedRequest(headers: Record<string, string> = {}): Request {
  return new Request(MCP_RESOURCE, {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      authorization: "Bearer security-regression-token",
      "content-type": "application/json",
      host: "kundenleicht.at",
      ...headers,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("security regression", () => {
  it("rejects untrusted browser origins and host headers after token validation", async () => {
    const server = createAdminResourceServer({
      validateToken: () => () => Promise.resolve(ADMIN_CONTEXT),
    });

    const wrongOrigin = await server.fetch(
      authenticatedRequest({ origin: "https://attacker.example" }),
      env,
      createExecutionContext(),
    );
    const wrongHost = await server.fetch(
      authenticatedRequest({ host: "attacker.example" }),
      env,
      createExecutionContext(),
    );

    expect(wrongOrigin.status).toBe(403);
    expect(wrongHost.status).toBe(403);
    expect(await wrongOrigin.text()).not.toContain("security-regression-token");
    expect(await wrongHost.text()).not.toContain("security-regression-token");
  });

  it("never writes OAuth state, codes, bearer credentials, or upstream errors to logs", async () => {
    const sentinels = [
      "SENTINEL-OAUTH-STATE",
      "SENTINEL-GOOGLE-CODE",
      "SENTINEL-BEARER-TOKEN",
      "SENTINEL-UPSTREAM-ERROR",
    ];
    const captures: unknown[][] = [];
    for (const method of ["debug", "error", "info", "log", "warn"] as const) {
      vi.spyOn(console, method).mockImplementation((...values: unknown[]) => {
        captures.push(values);
      });
    }

    const callback = await createOAuthRouter().fetch(
      new Request(
        `${MCP_RESOURCE}/google/callback?code=SENTINEL-GOOGLE-CODE&state=SENTINEL-OAUTH-STATE`,
      ),
      env,
      createExecutionContext(),
    );
    const invalidTokenServer = createAdminResourceServer({
      validateToken: () => () => Promise.resolve(null),
    });
    const rejected = await invalidTokenServer.fetch(
      authenticatedRequest({ authorization: "Bearer SENTINEL-BEARER-TOKEN" }),
      env,
      createExecutionContext(),
    );
    const upstreamFailureServer = createAdminResourceServer({
      validateToken: () => () => Promise.resolve(ADMIN_CONTEXT),
      fetchFn: () => Promise.reject(new Error("SENTINEL-UPSTREAM-ERROR")),
    });
    const upstreamFailure = await upstreamFailureServer.fetch(
      new Request(MCP_RESOURCE, {
        method: "POST",
        headers: {
          accept: "application/json, text/event-stream",
          authorization: "Bearer security-regression-token",
          "content-type": "application/json",
          host: "kundenleicht.at",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "composio_connection_check", arguments: {} },
        }),
      }),
      env,
      createExecutionContext(),
    );

    const publicMaterial = [
      await callback.text(),
      await rejected.text(),
      await upstreamFailure.text(),
    ].join("\n");
    const loggedMaterial = captures
      .flatMap((values) => values.map((value) => String(value)))
      .join("\n");
    for (const sentinel of sentinels) {
      expect(publicMaterial).not.toContain(sentinel);
      expect(loggedMaterial).not.toContain(sentinel);
    }
  });
});
