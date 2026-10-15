import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTVerifyGetKey,
} from "jose";

const GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_JWKS = createRemoteJWKSet(
  new URL("https://www.googleapis.com/oauth2/v3/certs"),
  { timeoutDuration: 10_000, cooldownDuration: 30_000, cacheMaxAge: 300_000 },
);

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function s256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest));
}

export class GoogleIdentityError extends Error {
  constructor(readonly code: "token_exchange_failed" | "invalid_identity_token" | "administrator_not_allowed") {
    super(code);
    this.name = "GoogleIdentityError";
  }
}

export async function createPkcePair(): Promise<{ verifier: string; challenge: string }> {
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const verifier = base64Url(random);
  return { verifier, challenge: await s256(verifier) };
}

export async function buildGoogleAuthorizationUrl(options: {
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  codeVerifier: string;
}): Promise<URL> {
  const url = new URL(GOOGLE_AUTHORIZE_URL);
  url.searchParams.set("client_id", options.clientId);
  url.searchParams.set("redirect_uri", options.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", options.state);
  url.searchParams.set("nonce", options.nonce);
  url.searchParams.set("code_challenge", await s256(options.codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("prompt", "select_account");
  return url;
}

export async function exchangeGoogleCode(
  options: {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    code: string;
    codeVerifier: string;
  },
  fetchFn: typeof fetch = fetch,
): Promise<{ idToken: string }> {
  const body = new URLSearchParams({
    client_id: options.clientId,
    client_secret: options.clientSecret,
    code: options.code,
    code_verifier: options.codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: options.redirectUri,
  });

  let response: Response;
  try {
    response = await fetchFn(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new GoogleIdentityError("token_exchange_failed");
  }

  if (!response.ok) {
    await response.body?.cancel();
    throw new GoogleIdentityError("token_exchange_failed");
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new GoogleIdentityError("token_exchange_failed");
  }
  const idToken =
    typeof payload === "object" && payload !== null && "id_token" in payload
      ? (payload as { id_token?: unknown }).id_token
      : undefined;
  if (typeof idToken !== "string" || idToken.length === 0 || idToken.length > 16_384) {
    throw new GoogleIdentityError("token_exchange_failed");
  }
  return { idToken };
}

export async function verifyGoogleIdToken(
  idToken: string,
  options: {
    clientId: string;
    expectedNonce: string;
    allowedEmail: string;
    keyResolver?: JWTVerifyGetKey;
  },
): Promise<{
  sub: string;
  userId: string;
  email: string;
  emailVerified: true;
}> {
  try {
    const { payload } = await jwtVerify(idToken, options.keyResolver ?? GOOGLE_JWKS, {
      algorithms: ["RS256"],
      audience: options.clientId,
      issuer: ["https://accounts.google.com", "accounts.google.com"],
      clockTolerance: 5,
      maxTokenAge: "10m",
    });

    if (
      payload.nonce !== options.expectedNonce ||
      typeof payload.exp !== "number" ||
      typeof payload.iat !== "number" ||
      payload.aud !== options.clientId ||
      (payload.azp !== undefined && payload.azp !== options.clientId)
    ) {
      throw new GoogleIdentityError("invalid_identity_token");
    }

    const sub = typeof payload.sub === "string" ? payload.sub : "";
    const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
    if (
      sub.length === 0 ||
      !/^[0-9]{1,64}$/u.test(sub) ||
      payload.email_verified !== true ||
      email !== options.allowedEmail.trim().toLowerCase()
    ) {
      throw new GoogleIdentityError("administrator_not_allowed");
    }

    return {
      sub,
      userId: `google-${sub}`,
      email,
      emailVerified: true,
    };
  } catch (error) {
    if (error instanceof GoogleIdentityError) throw error;
    throw new GoogleIdentityError("invalid_identity_token");
  }
}
