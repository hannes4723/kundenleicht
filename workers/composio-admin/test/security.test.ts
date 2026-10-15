import { describe, expect, it } from "vitest";
import {
  escapeHtml,
  hardenedHtmlHeaders,
  publicJsonError,
  safeSecurityEvent,
} from "../src/security";

describe("security response helpers", () => {
  it("escapes all client-controlled HTML metacharacters", () => {
    expect(escapeHtml(`<script a="x">'&</script>`)).toBe(
      "&#60;script a=&#34;x&#34;&#62;&#39;&#38;&#60;/script&#62;",
    );
  });

  it("sets no-store, no-frame, no-referrer, and restrictive CSP headers", () => {
    const headers = hardenedHtmlHeaders();

    expect(headers.get("cache-control")).toBe("no-store");
    expect(headers.get("x-frame-options")).toBe("DENY");
    expect(headers.get("referrer-policy")).toBe("no-referrer");
    expect(headers.get("x-content-type-options")).toBe("nosniff");
    expect(headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(headers.get("content-security-policy")).toContain("form-action 'self'");
  });

  it("returns a stable public error without diagnostic or secret material", async () => {
    const secret = "very-sensitive-token";
    const response = publicJsonError("authentication_failed", 401, {
      cause: new Error(`upstream said ${secret}`),
    });

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = await response.text();
    expect(body).toBe('{"error":"authentication_failed"}');
    expect(body).not.toContain(secret);
  });

  it("only admits allow-listed scalar fields into security events", () => {
    const event = safeSecurityEvent("oauth_denied", {
      requestId: "req-123",
      reason: "identity_not_allowed",
      token: "must-not-appear",
      authorization: "Bearer must-not-appear",
      nested: { secret: "must-not-appear" },
    });

    expect(event).toEqual({
      event: "oauth_denied",
      requestId: "req-123",
      reason: "identity_not_allowed",
    });
    expect(JSON.stringify(event)).not.toContain("must-not-appear");
  });
});
