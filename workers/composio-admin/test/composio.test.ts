import { describe, expect, it } from "vitest";
import { ComposioError, createComposioClient } from "../src/composio";

const API_KEY = "composio-test-key-never-log";

function jsonFetch(payload: unknown, capture?: (request: Request) => void): typeof fetch {
  return (input, init) => {
    const request = new Request(input, init);
    capture?.(request);
    return Promise.resolve(Response.json(payload));
  };
}

describe("Composio read client", () => {
  it("checks authentication with a minimal read and returns status only", async () => {
    let captured: Request | undefined;
    const client = createComposioClient({
      apiKey: API_KEY,
      fetchFn: jsonFetch({ items: [] }, (request) => {
        captured = request;
      }),
    });

    const result = await client.connectionCheck();

    expect(result).toEqual({ authenticated: true, httpStatus: 200 });
    expect(captured?.url).toBe("https://backend.composio.dev/api/v3.1/toolkits?limit=1");
    expect(captured?.headers.get("x-api-key")).toBe(API_KEY);
    expect(captured?.headers.get("authorization")).toBeNull();
  });

  it("lists toolkit metadata through a strict safe projection", async () => {
    let captured: Request | undefined;
    const payload = {
      items: [
        {
          slug: "gmail",
          name: "Gmail",
          auth_schemes: ["OAUTH2"],
          composio_managed_auth_schemes: ["OAUTH2"],
          meta: {
            description: "Google mail",
            logo: "https://cdn.example/gmail.svg",
            app_url: "https://mail.google.com",
            tools_count: 44,
            triggers_count: 5,
            categories: [{ id: "communication", name: "Communication", secret: "omit" }],
            available_versions: ["20261001_00"],
            hidden_token: "must-not-appear",
          },
          state: { oauth_token: "must-not-appear" },
        },
      ],
      next_cursor: "next-page",
      internal_secret: "must-not-appear",
    };
    const client = createComposioClient({
      apiKey: API_KEY,
      fetchFn: jsonFetch(payload, (request) => {
        captured = request;
      }),
    });

    const result = await client.listToolkits({ limit: 10, search: "mail", cursor: "cursor-1" });

    expect(result).toEqual({
      items: [
        {
          slug: "gmail",
          name: "Gmail",
          description: "Google mail",
          logoUrl: "https://cdn.example/gmail.svg",
          appUrl: "https://mail.google.com/",
          authSchemes: ["OAUTH2"],
          categories: [{ slug: "communication", name: "Communication" }],
          toolsCount: 44,
          triggersCount: 5,
          availableVersions: ["20261001_00"],
        },
      ],
      nextCursor: "next-page",
    });
    expect(captured?.url).toContain("limit=10");
    expect(captured?.url).toContain("search=mail");
    expect(captured?.url).toContain("cursor=cursor-1");
    expect(JSON.stringify(result)).not.toContain("must-not-appear");
  });

  it("gets a toolkit by validated slug without returning arbitrary fields", async () => {
    let captured: Request | undefined;
    const client = createComposioClient({
      apiKey: API_KEY,
      fetchFn: jsonFetch(
        {
          slug: "github",
          name: "GitHub",
          auth_schemes: ["OAUTH2", "API_KEY"],
          meta: { description: "Git hosting", tools_count: 80 },
          credentials: { api_key: "must-not-appear" },
        },
        (request) => {
          captured = request;
        },
      ),
    });

    const result = await client.getToolkit("github");

    expect(result.slug).toBe("github");
    expect(result.authSchemes).toEqual(["OAUTH2", "API_KEY"]);
    expect(captured?.url).toBe(
      "https://backend.composio.dev/api/v3.1/toolkits/github?version=latest",
    );
    expect(JSON.stringify(result)).not.toContain("must-not-appear");
  });

  it("lists connection status while dropping state, data, params, and credentials", async () => {
    let captured: Request | undefined;
    const payload = {
      items: [
        {
          id: "ca_123",
          toolkit: { slug: "gmail" },
          auth_config: {
            id: "ac_123",
            auth_scheme: "OAUTH2",
            is_composio_managed: false,
            is_disabled: false,
          },
          alias: "work",
          user_id: "user-42",
          status: "ACTIVE",
          status_reason: "provider body may contain secrets",
          is_disabled: false,
          experimental: { account_type: "PRIVATE", acl_config_for_shared: { allowed_user_ids: [] } },
          created_at: "2026-10-01T12:00:00Z",
          updated_at: "2026-10-02T12:00:00Z",
          state: { val: { oauth_token: "must-not-appear", proxy_password: "must-not-appear" } },
          data: { api_key: "must-not-appear" },
          params: { authorization: "Bearer must-not-appear" },
          test_request_endpoint: "https://sensitive.example",
        },
      ],
      next_cursor: null,
    };
    const client = createComposioClient({
      apiKey: API_KEY,
      fetchFn: jsonFetch(payload, (request) => {
        captured = request;
      }),
    });

    const result = await client.listConnections({
      limit: 25,
      toolkitSlugs: ["gmail"],
      statuses: ["ACTIVE"],
      userIds: ["user-42"],
      cursor: "connections-page-2",
    });

    expect(result).toEqual({
      items: [
        {
          id: "ca_123",
          toolkitSlug: "gmail",
          authConfigId: "ac_123",
          authScheme: "OAUTH2",
          isComposioManaged: false,
          alias: "work",
          userId: "user-42",
          status: "ACTIVE",
          isDisabled: false,
          accountType: "PRIVATE",
          createdAt: "2026-10-01T12:00:00Z",
          updatedAt: "2026-10-02T12:00:00Z",
        },
      ],
    });
    const url = new URL(captured?.url ?? "https://invalid.example");
    expect(url.searchParams.getAll("toolkit_slugs")).toEqual(["gmail"]);
    expect(url.searchParams.getAll("statuses")).toEqual(["ACTIVE"]);
    expect(url.searchParams.getAll("user_ids")).toEqual(["user-42"]);
    expect(url.searchParams.get("cursor")).toBe("connections-page-2");
    expect(JSON.stringify(result)).not.toContain("must-not-appear");
    expect(JSON.stringify(result)).not.toContain("status_reason");
  });

  it.each([
    ["invalid toolkit slug", () => createComposioClient({ apiKey: API_KEY }).getToolkit("../secret")],
    ["excessive page size", () => createComposioClient({ apiKey: API_KEY }).listToolkits({ limit: 1001 })],
    ["empty API key", () => createComposioClient({ apiKey: "" }).connectionCheck()],
  ])("rejects %s before an unsafe request", async (_label, operation) => {
    await expect(operation()).rejects.toBeInstanceOf(ComposioError);
    await expect(operation()).rejects.toMatchObject({ code: "invalid_input" });
  });

  it("maps upstream failures without including response bodies, keys, or URLs", async () => {
    const leaked = "oauth_token=must-not-appear";
    const client = createComposioClient({
      apiKey: API_KEY,
      fetchFn: () =>
        Promise.resolve(new Response(JSON.stringify({ error: leaked }), { status: 500 })),
    });

    let thrown: unknown;
    try {
      await client.listToolkits();
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(ComposioError);
    expect((thrown as ComposioError).code).toBe("upstream_rejected");
    expect(String(thrown)).not.toContain(leaked);
    expect(String(thrown)).not.toContain(API_KEY);
  });

  it("maps network errors without exposing their diagnostic text", async () => {
    const leaked = "Bearer must-not-appear";
    const client = createComposioClient({
      apiKey: API_KEY,
      fetchFn: () => Promise.reject(new Error(leaked)),
    });

    await expect(client.listConnections()).rejects.toMatchObject({
      code: "upstream_unavailable",
    });
    await expect(client.listConnections()).rejects.not.toThrow(leaked);
  });

  it("cancels an unknown-length response as soon as it exceeds the byte limit", async () => {
    let pulls = 0;
    let cancelled = false;
    const chunk = new Uint8Array(1_100_000).fill(65);
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(chunk);
        if (pulls >= 10) controller.close();
      },
      cancel() {
        cancelled = true;
      },
    });
    const client = createComposioClient({
      apiKey: API_KEY,
      fetchFn: () => Promise.resolve(new Response(body)),
    });

    await expect(client.listToolkits()).rejects.toMatchObject({ code: "invalid_response" });
    expect(cancelled).toBe(true);
    expect(pulls).toBeLessThan(10);
  });
});
