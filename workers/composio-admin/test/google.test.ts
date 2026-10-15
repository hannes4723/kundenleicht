import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JWTVerifyGetKey,
} from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  GoogleIdentityError,
  buildGoogleAuthorizationUrl,
  createPkcePair,
  exchangeGoogleCode,
  verifyGoogleIdToken,
} from "../src/google";

const CLIENT_ID = "google-client.apps.googleusercontent.com";
const REDIRECT_URI = "https://kundenleicht.at/mcp/admin/google/callback";
const NONCE = "nonce-for-test";
const ALLOWED_EMAIL = "hannes4723@gmail.com";

let privateKey: CryptoKey;
let keyResolver: JWTVerifyGetKey;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  privateKey = pair.privateKey;
  const publicJwk = await exportJWK(pair.publicKey);
  publicJwk.kid = "google-test-key";
  publicJwk.alg = "RS256";
  keyResolver = createLocalJWKSet({ keys: [publicJwk] });
});

async function idToken(
  overrides: {
    audience?: string | string[];
    authorizedParty?: string;
    email?: string;
    emailVerified?: boolean;
    issuer?: string;
    nonce?: string;
    subject?: string;
    expiresAt?: number;
    issuedAt?: number;
  } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    email: overrides.email ?? ALLOWED_EMAIL,
    email_verified: overrides.emailVerified ?? true,
    nonce: overrides.nonce ?? NONCE,
    ...(overrides.authorizedParty ? { azp: overrides.authorizedParty } : {}),
  })
    .setProtectedHeader({ alg: "RS256", kid: "google-test-key", typ: "JWT" })
    .setIssuer(overrides.issuer ?? "https://accounts.google.com")
    .setAudience(overrides.audience ?? CLIENT_ID)
    .setSubject(overrides.subject ?? "109876543210987654321")
    .setIssuedAt(overrides.issuedAt ?? now)
    .setExpirationTime(overrides.expiresAt ?? now + 300)
    .sign(privateKey);
}

describe("Google upstream OAuth", () => {
  it("creates independent high-entropy PKCE verifier and S256 challenge", async () => {
    const first = await createPkcePair();
    const second = await createPkcePair();

    expect(first.verifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    expect(first.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.challenge).not.toBe(first.verifier);
    expect(second.verifier).not.toBe(first.verifier);
  });

  it("builds a Google OIDC URL with state, nonce, and upstream PKCE", async () => {
    const url = await buildGoogleAuthorizationUrl({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      state: "browser-bound-state",
      nonce: NONCE,
      codeVerifier: "0123456789012345678901234567890123456789012",
    });

    expect(url.origin + url.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid email profile");
    expect(url.searchParams.get("state")).toBe("browser-bound-state");
    expect(url.searchParams.get("nonce")).toBe(NONCE);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("exchanges a Google code with the upstream PKCE verifier", async () => {
    let capturedBody = "";
    const fetchFn: typeof fetch = (_input, init) => {
      capturedBody = init?.body instanceof URLSearchParams ? init.body.toString() : "";
      return Promise.resolve(
        Response.json({ id_token: "signed-id-token", access_token: "discard-me" }),
      );
    };

    const result = await exchangeGoogleCode(
      {
        clientId: CLIENT_ID,
        clientSecret: "client-secret-test-value",
        redirectUri: REDIRECT_URI,
        code: "one-time-code",
        codeVerifier: "upstream-pkce-verifier",
      },
      fetchFn,
    );

    const body = new URLSearchParams(capturedBody);
    expect(result).toEqual({ idToken: "signed-id-token" });
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code_verifier")).toBe("upstream-pkce-verifier");
    expect(body.get("client_secret")).toBe("client-secret-test-value");
  });

  it("does not expose Google's error body or submitted credentials", async () => {
    const upstreamLeak = "upstream-access-token-secret";
    const fetchFn: typeof fetch = () =>
      Promise.resolve(
        new Response(JSON.stringify({ error_description: upstreamLeak }), { status: 401 }),
      );

    let thrown: unknown;
    try {
      await exchangeGoogleCode(
        {
          clientId: CLIENT_ID,
          clientSecret: "client-secret-test-value",
          redirectUri: REDIRECT_URI,
          code: "one-time-code",
          codeVerifier: "upstream-pkce-verifier",
        },
        fetchFn,
      );
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(GoogleIdentityError);
    expect(String(thrown)).not.toContain(upstreamLeak);
    expect(String(thrown)).not.toContain("client-secret-test-value");
    expect((thrown as GoogleIdentityError).code).toBe("token_exchange_failed");
  });
});

describe("Google ID token verification", () => {
  it("accepts only the verified allow-listed administrator and returns stable identity", async () => {
    const identity = await verifyGoogleIdToken(await idToken(), {
      clientId: CLIENT_ID,
      expectedNonce: NONCE,
      allowedEmail: ALLOWED_EMAIL,
      keyResolver,
    });

    expect(identity).toEqual({
      sub: "109876543210987654321",
      userId: "google-109876543210987654321",
      email: ALLOWED_EMAIL,
      emailVerified: true,
    });
  });

  it.each([
    ["wrong audience", { audience: "another-client" }],
    ["wrong issuer", { issuer: "https://attacker.example" }],
    ["expired token", { expiresAt: 1, issuedAt: 1 }],
    ["wrong nonce", { nonce: "other-nonce" }],
  ])("rejects %s", async (_label, overrides) => {
    await expect(
      verifyGoogleIdToken(await idToken(overrides), {
        clientId: CLIENT_ID,
        expectedNonce: NONCE,
        allowedEmail: ALLOWED_EMAIL,
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: "invalid_identity_token" });
  });

  it("rejects a multi-audience token even when one audience is the Google client", async () => {
    await expect(
      verifyGoogleIdToken(
        await idToken({
          audience: [CLIENT_ID, "other-client.apps.googleusercontent.com"],
          authorizedParty: "other-client.apps.googleusercontent.com",
        }),
        {
          clientId: CLIENT_ID,
          expectedNonce: NONCE,
          allowedEmail: ALLOWED_EMAIL,
          keyResolver,
        },
      ),
    ).rejects.toMatchObject({ code: "invalid_identity_token" });
  });

  it.each([
    ["wrong email", { email: "attacker@example.com" }],
    ["unverified email", { emailVerified: false }],
    ["missing subject", { subject: "" }],
  ])("rejects %s before authorization", async (_label, overrides) => {
    await expect(
      verifyGoogleIdToken(await idToken(overrides), {
        clientId: CLIENT_ID,
        expectedNonce: NONCE,
        allowedEmail: ALLOWED_EMAIL,
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: "administrator_not_allowed" });
  });
});
