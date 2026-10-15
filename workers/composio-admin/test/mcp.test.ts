import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  MCP_RESOURCE,
  READ_SCOPE,
  type AdminAuthorizationProps,
} from "../src/oauth";
import { createAdminResourceServer } from "../src/mcp";

const VALID_PROPS: AdminAuthorizationProps = {
  googleSub: "109876543210987654321",
  email: "hannes4723@gmail.com",
  emailVerified: true,
  role: "admin",
};

function validatorResult(overrides: Record<string, unknown> = {}) {
  return {
    props: VALID_PROPS,
    audience: MCP_RESOURCE,
    expiresAt: Math.floor(Date.now() / 1000) + 3_600,
    scope: [READ_SCOPE],
    userId: "google-109876543210987654321",
    clientId: "chatgpt-client",
    ...overrides,
  };
}

function serverWithValidation(
  result: ReturnType<typeof validatorResult> | null,
  fetchFn?: typeof fetch,
) {
  return createAdminResourceServer({
    validateToken: () => () => Promise.resolve(result),
    ...(fetchFn ? { fetchFn } : {}),
  });
}

function mcpRequest(body: unknown, token = "valid-access-token"): Request {
  return new Request(MCP_RESOURCE, {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      host: "kundenleicht.at",
      "mcp-protocol-version": "2025-06-18",
    },
    body: JSON.stringify(body),
  });
}

async function call(server: ReturnType<typeof createAdminResourceServer>, body: unknown) {
  return server.fetch(mcpRequest(body), env, createExecutionContext());
}

async function readMcpResponse<T>(response: Response): Promise<T> {
  const text = await response.text();
  if (response.headers.get("content-type")?.includes("text/event-stream")) {
    const data = text
      .split("\n")
      .find((line) => line.startsWith("data: "))
      ?.slice("data: ".length);
    if (!data) throw new Error("MCP SSE response did not contain a data event");
    return JSON.parse(data) as T;
  }
  return JSON.parse(text) as T;
}

describe("OAuth MCP resource server", () => {
  it("publishes protected-resource metadata for the path-bound resource", async () => {
    const response = await serverWithValidation(null).fetch(
      new Request(
        "https://kundenleicht.at/.well-known/oauth-protected-resource/mcp/admin",
      ),
      env,
      createExecutionContext(),
    );

    expect(response.status).toBe(200);
    const metadata = await response.json<Record<string, unknown>>();
    expect(metadata.resource).toBe(MCP_RESOURCE);
    expect(metadata.authorization_servers).toEqual([MCP_RESOURCE]);
    expect(metadata.scopes_supported).toEqual([READ_SCOPE]);
    expect(metadata.bearer_methods_supported).toEqual(["header"]);
  });

  it("rejects missing and invalid bearer tokens with a discoverable challenge", async () => {
    const server = serverWithValidation(null);
    const missing = await server.fetch(
      new Request(MCP_RESOURCE, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
      env,
      createExecutionContext(),
    );
    const invalid = await server.fetch(
      mcpRequest({ jsonrpc: "2.0", id: 1, method: "ping" }, "invalid"),
      env,
      createExecutionContext(),
    );

    for (const response of [missing, invalid]) {
      expect(response.status).toBe(401);
      const challenge = response.headers.get("www-authenticate") ?? "";
      expect(challenge).toContain("Bearer");
      expect(challenge).toContain("resource_metadata=");
      expect(challenge).toContain(`scope="${READ_SCOPE}"`);
    }
  });

  it("rejects expired, wrong-resource, wrong-scope, and wrong-identity contexts", async () => {
    const expired = await serverWithValidation(
      validatorResult({ expiresAt: Math.floor(Date.now() / 1000) - 1 }),
    ).fetch(mcpRequest({ jsonrpc: "2.0", id: 1, method: "ping" }), env, createExecutionContext());
    expect(expired.status).toBe(401);

    const wrongResource = await serverWithValidation(
      validatorResult({ audience: "https://kundenleicht.at/another-resource" }),
    ).fetch(mcpRequest({ jsonrpc: "2.0", id: 1, method: "ping" }), env, createExecutionContext());
    expect(wrongResource.status).not.toBe(200);

    const wrongScope = await serverWithValidation(validatorResult({ scope: [] })).fetch(
      mcpRequest({ jsonrpc: "2.0", id: 1, method: "ping" }),
      env,
      createExecutionContext(),
    );
    expect(wrongScope.status).toBe(403);
    expect(wrongScope.headers.get("www-authenticate")).toContain("insufficient_scope");

    const wrongIdentity = await serverWithValidation(
      validatorResult({ props: { ...VALID_PROPS, email: "attacker@example.com" } }),
    ).fetch(mcpRequest({ jsonrpc: "2.0", id: 1, method: "ping" }), env, createExecutionContext());
    expect(wrongIdentity.status).toBe(403);
    expect(await wrongIdentity.text()).not.toContain("attacker@example.com");
  });

  it("initializes current stateless MCP and exposes only five read-only tools", async () => {
    const server = serverWithValidation(validatorResult());
    const initialized = await call(server, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "security-test", version: "1.0.0" },
      },
    });
    expect(initialized.status, await initialized.clone().text()).toBe(200);
    const initializedBody = await readMcpResponse<Record<string, unknown>>(initialized);
    expect(initializedBody).toMatchObject({ jsonrpc: "2.0", id: 1 });

    const listed = await call(server, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    });
    expect(listed.status).toBe(200);
    const payload = await readMcpResponse<{
      result: { tools: Array<{ name: string; annotations?: Record<string, unknown>; _meta?: Record<string, unknown> }> };
    }>(listed);
    const names = payload.result.tools.map((tool) => tool.name);
    expect(names).toEqual([
      "admin_profile",
      "composio_connection_check",
      "composio_list_toolkits",
      "composio_get_toolkit",
      "composio_list_connections",
    ]);
    expect(names.join(" ")).not.toMatch(/create|delete|remove|update|write|execute/iu);
    for (const tool of payload.result.tools) {
      expect(tool.annotations).toMatchObject({
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
      });
      expect(tool._meta?.securitySchemes).toEqual([
        { type: "oauth2", scopes: [READ_SCOPE] },
      ]);
    }
  });

  it("returns the stable administrator profile without exposing a bearer token", async () => {
    const response = await call(serverWithValidation(validatorResult()), {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "admin_profile", arguments: {} },
    });
    expect(response.status, await response.clone().text()).toBe(200);
    const body = await readMcpResponse<{
      result: { structuredContent: Record<string, unknown>; content: Array<{ text: string }> };
    }>(response);

    expect(body.result.structuredContent).toEqual({
      id: "kundenleicht-admin",
      role: "admin",
    });
    expect(JSON.stringify(body)).not.toContain("valid-access-token");
  });

  it("executes a sanitized real-shape Composio read through MCP", async () => {
    const fetchFn: typeof fetch = (input) => {
      const rawUrl =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      const url = new URL(rawUrl);
      if (url.pathname.endsWith("/toolkits") && url.searchParams.get("limit") === "1") {
        return Promise.resolve(Response.json({ items: [] }));
      }
      throw new Error("Unexpected Composio request");
    };
    const response = await call(serverWithValidation(validatorResult(), fetchFn), {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "composio_connection_check", arguments: {} },
    });
    expect(response.status, await response.clone().text()).toBe(200);
    const body = await readMcpResponse<{
      result: { structuredContent: Record<string, unknown>; isError?: boolean };
    }>(response);

    expect(body.result.structuredContent).toEqual({ authenticated: true, httpStatus: 200 });
    expect(body.result.isError).not.toBe(true);
  });

  it("rejects unknown tools and oversized MCP requests without dispatching them", async () => {
    const server = serverWithValidation(validatorResult());
    const unknown = await call(server, {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "composio_delete_connection", arguments: {} },
    });
    const unknownBody = await readMcpResponse<Record<string, unknown>>(unknown);
    expect(unknown.status).toBe(200);
    expect(JSON.stringify(unknownBody)).toMatch(/unknown|not found/iu);

    const oversized = await server.fetch(
      new Request(MCP_RESOURCE, {
        method: "POST",
        headers: {
          authorization: "Bearer valid-access-token",
          "content-length": "262145",
          "content-type": "application/json",
          host: "kundenleicht.at",
        },
        body: "{}",
      }),
      env,
      createExecutionContext(),
    );
    expect(oversized.status).toBe(413);
    expect(await oversized.json()).toEqual({ error: "request_too_large" });

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(262_145));
        controller.close();
      },
    });
    const undeclaredOversized = await server.fetch(
      new Request(MCP_RESOURCE, {
        method: "POST",
        headers: {
          authorization: "Bearer valid-access-token",
          "content-type": "application/json",
          host: "kundenleicht.at",
        },
        body: stream,
      }),
      env,
      createExecutionContext(),
    );
    expect(undeclaredOversized.status).toBe(413);
  });
});
