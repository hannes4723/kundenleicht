import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

describe("test harness", () => {
  it("provides isolated OAuth KV and non-secret test bindings", async () => {
    await env.OAUTH_KV.put("smoke", "ready");

    expect(await env.OAUTH_KV.get("smoke")).toBe("ready");
    expect(env.COMPOSIO_API_KEY).toBe("test-composio-api-key");
  });
});
