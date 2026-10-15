import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JWTVerifyGetKey,
} from "jose";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  AUTHORIZATION_SERVER_ISSUER,
  GOOGLE_CALLBACK_URL,
  MCP_RESOURCE,
  READ_SCOPE,
  authorizationServer,
  createOAuthRouter,
} from "../src/oauth";

const REDIRECT_URI = "https://client.example/oauth/callback";
const CODE_VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

let privateKey: CryptoKey;
let keyResolver: JWTVerifyGetKey;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  privateKey = pair.privateKey;
  const jwk = await exportJWK(pair.publicKey);
  jwk.kid = "oauth-integration-key";
  jwk.alg = "RS256";
  keyResolver = createLocalJWKSet({ keys: [jwk] });
});

afterEach(() => {
  vi.useRealTimers();
});

async function s256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function cookies(response: Response): string {
  return response.headers
    .getSetCookie()
    .map((value) => value.split(";", 1)[0])
    .join("; ");
}

function hiddenHandle(html: string): string {
  const match = /name="handle" value="([^"]+)"/u.exec(html);
  if (!match?.[1]) throw new Error("Consent handle missing");
  return match[1];
}

function upstreamHref(html: string): string {
  const match = /<a href="([^"]+)" rel="noreferrer">Weiter zu Google<\/a>/u.exec(html);
  if (!match?.[1]) throw new Error("Google transition link missing");
  return match[1].replaceAll("&#38;", "&");
}

async function registerClient(): Promise<string> {
  const response = await authorizationServer.fetch(
    new Request(`${AUTHORIZATION_SERVER_ISSUER}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "OAuth integration test",
        redirect_uris: [REDIRECT_URI],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }),
    }),
    env,
    createExecutionContext(),
  );
  expect(response.status).toBe(201);
  const payload = await response.json<{ client_id: string }>();
  return payload.client_id;
}

async function beginFlow(router: ReturnType<typeof createOAuthRouter>) {
  const clientId = await registerClient();
  const url = new URL(`${AUTHORIZATION_SERVER_ISSUER}/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", READ_SCOPE);
  url.searchParams.set("state", "chatgpt-client-state");
  url.searchParams.set("resource", MCP_RESOURCE);
  url.searchParams.set("code_challenge", await s256(CODE_VERIFIER));
  url.searchParams.set("code_challenge_method", "S256");

  const consent = await router.fetch(
    new Request(url),
    env,
    createExecutionContext(),
  );
  expect(consent.status).toBe(200);
  const consentHtml = await consent.text();
  const consentCookie = cookies(consent);
  const handle = hiddenHandle(consentHtml);

  const form = new FormData();
  form.set("handle", handle);
  form.set("decision", "approve");
  form.set("scope", READ_SCOPE);
  const googleRedirect = await router.fetch(
    new Request(`${AUTHORIZATION_SERVER_ISSUER}/authorize`, {
      method: "POST",
      headers: { cookie: consentCookie },
      body: form,
    }),
    env,
    createExecutionContext(),
  );
  expect(googleRedirect.status).toBe(200);
  expect(googleRedirect.headers.get("location")).toBeNull();
  expect(googleRedirect.headers.get("cache-control")).toBe("no-store");
  expect(googleRedirect.headers.get("referrer-policy")).toBe("no-referrer");
  expect(googleRedirect.headers.get("x-frame-options")).toBe("DENY");
  const transitionHtml = await googleRedirect.text();
  expect(transitionHtml).not.toContain('name="handle"');
  expect(transitionHtml).not.toContain("<script");
  const location = new URL(upstreamHref(transitionHtml));
  expect(location.origin).toBe("https://accounts.google.com");
  return {
    clientId,
    state: location.searchParams.get("state") ?? "",
    nonce: location.searchParams.get("nonce") ?? "",
    callbackCookie: cookies(googleRedirect),
  };
}

async function signedGoogleIdToken(nonce: string, email = "hannes4723@gmail.com"): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ email, email_verified: true, nonce })
    .setProtectedHeader({ alg: "RS256", kid: "oauth-integration-key" })
    .setIssuer("https://accounts.google.com")
    .setAudience(env.GOOGLE_CLIENT_ID)
    .setSubject(email === "hannes4723@gmail.com" ? "109876543210987654321" : "999999999")
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);
}

function routerWithGoogleToken(tokenForNonce: (nonce: string) => Promise<string>) {
  let latestNonce = "";
  const fetchFn: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    if (request.url !== "https://oauth2.googleapis.com/token") {
      throw new Error("Unexpected outbound request");
    }
    const token = await tokenForNonce(latestNonce);
    return Response.json({ id_token: token, access_token: "discard-upstream-token" });
  };
  return {
    router: createOAuthRouter({
      fetchFn,
      keyResolver,
    }),
    setNonce: (nonce: string) => {
      latestNonce = nonce;
    },
  };
}

async function issueAuthorizationCode() {
  const { router, setNonce } = routerWithGoogleToken((nonce) => signedGoogleIdToken(nonce));
  const flow = await beginFlow(router);
  setNonce(flow.nonce);
  const callback = await router.fetch(
    new Request(`${GOOGLE_CALLBACK_URL}?code=google-code&state=${encodeURIComponent(flow.state)}`, {
      headers: { cookie: flow.callbackCookie },
    }),
    env,
    createExecutionContext(),
  );
  expect(callback.status).toBe(302);
  const authorizationRedirect = new URL(
    callback.headers.get("location") ?? "https://invalid.example",
  );
  const code = authorizationRedirect.searchParams.get("code") ?? "";
  expect(code).not.toBe("");
  return { flow, code, authorizationRedirect };
}

describe("OAuth authorization server", () => {
  it("publishes path-aware metadata for ChatGPT with S256, CIMD, DCR, and RFC 9207", async () => {
    const response = await authorizationServer.fetch(
      new Request(
        "https://kundenleicht.at/.well-known/oauth-authorization-server/mcp/admin",
      ),
      env,
      createExecutionContext(),
    );
    expect(response.status).toBe(200);
    const metadata = await response.json<Record<string, unknown>>();
    expect(metadata.issuer).toBe(AUTHORIZATION_SERVER_ISSUER);
    expect(metadata.authorization_endpoint).toBe(`${AUTHORIZATION_SERVER_ISSUER}/authorize`);
    expect(metadata.token_endpoint).toBe(`${AUTHORIZATION_SERVER_ISSUER}/oauth/token`);
    expect(metadata.registration_endpoint).toBe(`${AUTHORIZATION_SERVER_ISSUER}/oauth/register`);
    expect(metadata.code_challenge_methods_supported).toContain("S256");
    expect(metadata.client_id_metadata_document_supported).toBe(true);
    expect(metadata.authorization_response_iss_parameter_supported).toBe(true);
    expect(metadata.scopes_supported).toContain(READ_SCOPE);
  });

  it("renders escaped, non-frameable consent details and binds approval to its cookie", async () => {
    const router = createOAuthRouter();
    const clientId = await registerClient();
    const url = new URL(`${AUTHORIZATION_SERVER_ISSUER}/authorize`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", REDIRECT_URI);
    url.searchParams.set("scope", READ_SCOPE);
    url.searchParams.set("state", "client-state");
    url.searchParams.set("resource", MCP_RESOURCE);
    url.searchParams.set("code_challenge", await s256(CODE_VERIFIER));
    url.searchParams.set("code_challenge_method", "S256");

    const response = await router.fetch(new Request(url), env, createExecutionContext());
    const html = await response.text();
    expect(response.status).toBe(200);
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(html).toContain("OAuth integration test");
    expect(html).toContain("client.example");
    expect(html).toContain(READ_SCOPE);

    const form = new FormData();
    form.set("handle", hiddenHandle(html));
    form.set("decision", "approve");
    form.set("scope", READ_SCOPE);
    const forged = await router.fetch(
      new Request(`${AUTHORIZATION_SERVER_ISSUER}/authorize`, { method: "POST", body: form }),
      env,
      createExecutionContext(),
    );
    expect(forged.status).toBe(400);
  });

  it("rejects omitted or unsupported authorization scopes before creating consent state", async () => {
    const clientId = await registerClient();
    const request = async (scope?: string) => {
      const url = new URL(`${AUTHORIZATION_SERVER_ISSUER}/authorize`);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", clientId);
      url.searchParams.set("redirect_uri", REDIRECT_URI);
      url.searchParams.set("state", "scope-test-state");
      url.searchParams.set("resource", MCP_RESOURCE);
      url.searchParams.set("code_challenge", await s256(CODE_VERIFIER));
      url.searchParams.set("code_challenge_method", "S256");
      if (scope !== undefined) url.searchParams.set("scope", scope);
      return createOAuthRouter().fetch(new Request(url), env, createExecutionContext());
    };

    for (const response of [
      await request(),
      await request(`${READ_SCOPE} composio:write`),
      await request("composio:write"),
    ]) {
      expect(response.status).toBe(302);
      expect(new URL(response.headers.get("location") ?? REDIRECT_URI).searchParams.get("error"))
        .toBe("invalid_scope");
    }
  });

  it("rejects an undeclared oversized consent body before form parsing", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(`handle=${"x".repeat(17_000)}`));
        controller.close();
      },
    });
    const response = await createOAuthRouter().fetch(
      new Request(`${AUTHORIZATION_SERVER_ISSUER}/authorize`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: stream,
      }),
      env,
      createExecutionContext(),
    );

    expect(response.status).toBe(413);
  });

  it("rejects unregistered redirect URIs locally", async () => {
    const clientId = await registerClient();
    const url = new URL(`${AUTHORIZATION_SERVER_ISSUER}/authorize`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", "https://attacker.example/callback");
    url.searchParams.set("resource", MCP_RESOURCE);
    url.searchParams.set("code_challenge", await s256(CODE_VERIFIER));
    url.searchParams.set("code_challenge_method", "S256");

    const response = await createOAuthRouter().fetch(
      new Request(url),
      env,
      createExecutionContext(),
    );
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
  });

  it("rejects state tampering and state replay", async () => {
    const { router, setNonce } = routerWithGoogleToken((nonce) => signedGoogleIdToken(nonce));
    const first = await beginFlow(router);
    const tampered = await router.fetch(
      new Request(`${GOOGLE_CALLBACK_URL}?code=google-code&state=tampered`, {
        headers: { cookie: first.callbackCookie },
      }),
      env,
      createExecutionContext(),
    );
    expect(tampered.status).toBe(400);

    const second = await beginFlow(router);
    setNonce(second.nonce);
    const callbackRequest = () =>
      new Request(`${GOOGLE_CALLBACK_URL}?code=google-code&state=${encodeURIComponent(second.state)}`, {
        headers: { cookie: second.callbackCookie },
      });
    const success = await router.fetch(callbackRequest(), env, createExecutionContext());
    expect(success.status).toBe(302);
    expect(new URL(success.headers.get("location") ?? "https://invalid.example").origin).toBe(
      "https://client.example",
    );
    const replay = await router.fetch(callbackRequest(), env, createExecutionContext());
    expect(replay.status).toBe(400);
  });

  it("requires the browser-bound upstream cookie and the exact OIDC nonce", async () => {
    const missingCookie = routerWithGoogleToken((nonce) => signedGoogleIdToken(nonce));
    const first = await beginFlow(missingCookie.router);
    const withoutCookie = await missingCookie.router.fetch(
      new Request(
        `${GOOGLE_CALLBACK_URL}?code=google-code&state=${encodeURIComponent(first.state)}`,
      ),
      env,
      createExecutionContext(),
    );
    expect(withoutCookie.status).toBe(400);

    const wrongNonce = routerWithGoogleToken(() => signedGoogleIdToken("wrong-nonce"));
    const second = await beginFlow(wrongNonce.router);
    const rejected = await wrongNonce.router.fetch(
      new Request(
        `${GOOGLE_CALLBACK_URL}?code=google-code&state=${encodeURIComponent(second.state)}`,
        { headers: { cookie: second.callbackCookie } },
      ),
      env,
      createExecutionContext(),
    );
    expect(rejected.status).toBe(400);
  });

  it("rejects a valid Google token for the wrong identity before issuing a code", async () => {
    const { router, setNonce } = routerWithGoogleToken((nonce) =>
      signedGoogleIdToken(nonce, "attacker@example.com"),
    );
    const flow = await beginFlow(router);
    setNonce(flow.nonce);
    const response = await router.fetch(
      new Request(`${GOOGLE_CALLBACK_URL}?code=google-code&state=${encodeURIComponent(flow.state)}`, {
        headers: { cookie: flow.callbackCookie },
      }),
      env,
      createExecutionContext(),
    );
    expect(response.status).toBe(403);
    expect(response.headers.get("location")).toBeNull();
    expect(await response.text()).not.toContain("attacker@example.com");
  });

  it("rejects authorization-code replay after a successful exchange", async () => {
    const { flow, code } = await issueAuthorizationCode();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: flow.clientId,
      redirect_uri: REDIRECT_URI,
      code,
      code_verifier: CODE_VERIFIER,
      resource: MCP_RESOURCE,
    });
    const exchange = () =>
      authorizationServer.fetch(
        new Request(`${AUTHORIZATION_SERVER_ISSUER}/oauth/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body,
        }),
        env,
        createExecutionContext(),
      );

    expect((await exchange()).status).toBe(200);
    const replay = await exchange();
    expect(replay.status).toBe(400);
    expect(await replay.json<Record<string, unknown>>()).toMatchObject({
      error: "invalid_grant",
    });
  });

  it("enforces downstream PKCE and returns resource-bound rotating credentials", async () => {
    const { flow, code, authorizationRedirect } = await issueAuthorizationCode();
    expect(authorizationRedirect.searchParams.get("state")).toBe("chatgpt-client-state");
    expect(authorizationRedirect.searchParams.get("iss")).toBe(AUTHORIZATION_SERVER_ISSUER);

    const wrongVerifier = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: flow.clientId,
      redirect_uri: REDIRECT_URI,
      code,
      code_verifier: `${CODE_VERIFIER}wrong`,
      resource: MCP_RESOURCE,
    });
    const rejected = await authorizationServer.fetch(
      new Request(`${AUTHORIZATION_SERVER_ISSUER}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: wrongVerifier,
      }),
      env,
      createExecutionContext(),
    );
    expect(rejected.status).toBe(400);
    expect(await rejected.json<Record<string, unknown>>()).toMatchObject({ error: "invalid_grant" });

    const correctVerifier = new URLSearchParams(wrongVerifier);
    correctVerifier.set("code_verifier", CODE_VERIFIER);
    const accepted = await authorizationServer.fetch(
      new Request(`${AUTHORIZATION_SERVER_ISSUER}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: correctVerifier,
      }),
      env,
      createExecutionContext(),
    );
    expect(accepted.status).toBe(200);
    const tokens = await accepted.json<Record<string, unknown>>();
    expect(tokens.access_token).toEqual(expect.any(String));
    expect(tokens.refresh_token).toEqual(expect.any(String));
    expect(tokens.resource).toBe(MCP_RESOURCE);
    expect(tokens.scope).toContain(READ_SCOPE);
    expect(tokens.expires_in).toBe(3_600);

    const refresh = (refreshToken: string) =>
      authorizationServer.fetch(
        new Request(`${AUTHORIZATION_SERVER_ISSUER}/oauth/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            client_id: flow.clientId,
            refresh_token: refreshToken,
            resource: MCP_RESOURCE,
          }),
        }),
        env,
        createExecutionContext(),
      );
    const firstRefreshToken = String(tokens.refresh_token);
    const firstRotation = await refresh(firstRefreshToken);
    expect(firstRotation.status, await firstRotation.clone().text()).toBe(200);
    const firstRotatedTokens = await firstRotation.json<Record<string, unknown>>();
    const secondRefreshToken = String(firstRotatedTokens.refresh_token);
    expect(secondRefreshToken).not.toBe(firstRefreshToken);

    const secondRotation = await refresh(secondRefreshToken);
    expect(secondRotation.status).toBe(200);
    const secondRotatedTokens = await secondRotation.json<Record<string, unknown>>();
    const currentRefreshToken = String(secondRotatedTokens.refresh_token);
    const oldReplay = await refresh(firstRefreshToken);
    expect(oldReplay.status).toBe(400);
    expect(await oldReplay.json<Record<string, unknown>>()).toMatchObject({
      error: "invalid_grant",
    });

    const accessToken = String(tokens.access_token);
    expect(await authorizationServer.validateToken(MCP_RESOURCE, accessToken, env)).not.toBeNull();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 3_601_000);
    expect(await authorizationServer.validateToken(MCP_RESOURCE, accessToken, env)).toBeNull();
    vi.setSystemTime(Date.now() + 30 * 24 * 60 * 60 * 1_000);
    const expiredRefresh = await refresh(currentRefreshToken);
    expect(expiredRefresh.status).toBe(400);
    expect(await expiredRefresh.json<Record<string, unknown>>()).toMatchObject({
      error: "invalid_grant",
    });

  });
});
