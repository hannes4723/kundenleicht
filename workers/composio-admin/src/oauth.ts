import {
  AuthorizationError,
  CimdFetchError,
  OAuthAuthorizationServer,
  authorizationErrorRedirect,
} from "@cloudflare/workers-oauth-provider";
import type { JWTVerifyGetKey } from "jose";
import {
  GoogleIdentityError,
  buildGoogleAuthorizationUrl,
  createPkcePair,
  exchangeGoogleCode,
  verifyGoogleIdToken,
} from "./google";
import {
  consentPage,
  errorPage,
  googleTransitionPage,
  htmlResponse,
  redirectResponse,
} from "./pages";
import { BodyTooLargeError, readBodyWithLimit } from "./security";

export const AUTHORIZATION_SERVER_ISSUER = "https://kundenleicht.at/mcp/admin";
export const MCP_RESOURCE = "https://kundenleicht.at/mcp/admin";
export const GOOGLE_CALLBACK_URL = "https://kundenleicht.at/mcp/admin/google/callback";
export const READ_SCOPE = "composio:read";
export const ALLOWED_ADMIN_EMAIL = "hannes4723@gmail.com";

export interface AdminAuthorizationProps {
  googleSub: string;
  email: string;
  emailVerified: true;
  role: "admin";
}

export const authorizationServer = new OAuthAuthorizationServer<Cloudflare.Env>({
  issuer: AUTHORIZATION_SERVER_ISSUER,
  resources: [MCP_RESOURCE],
  defaultResource: MCP_RESOURCE,
  clientRegistrationEndpoint: `${AUTHORIZATION_SERVER_ISSUER}/oauth/register`,
  scopesSupported: [READ_SCOPE],
  accessTokenTTL: 3_600,
  refreshTokenTTL: 2_592_000,
  clientRegistrationTTL: 7_776_000,
  clientIdMetadataDocumentEnabled: true,
  cookiePrefix: "__Host-kla-oauth-",
  allowTokenExchangeGrant: false,
  onError: () => undefined,
});

export interface OAuthRouterDependencies {
  fetchFn?: typeof fetch;
  keyResolver?: JWTVerifyGetKey;
}

interface UpstreamState {
  codeVerifier: string;
  nonce: string;
}

const GENERIC_INVALID_REQUEST =
  "Die Anmeldung ist ungültig, abgelaufen oder wurde bereits verwendet. Bitte starten Sie sie erneut.";

function safeErrorResponse(error: unknown): Response {
  if (error instanceof AuthorizationError && error.redirectTo) {
    return redirectResponse(error.redirectTo);
  }
  if (error instanceof AuthorizationError || error instanceof CimdFetchError) {
    return htmlResponse(errorPage("Anmeldung nicht möglich", GENERIC_INVALID_REQUEST), 400);
  }
  if (error instanceof GoogleIdentityError) {
    const status = error.code === "administrator_not_allowed" ? 403 : 400;
    const message =
      error.code === "administrator_not_allowed"
        ? "Dieses Google-Konto ist für die Kundenleicht-Verwaltung nicht freigeschaltet."
        : GENERIC_INVALID_REQUEST;
    return htmlResponse(errorPage("Google-Anmeldung abgewiesen", message), status);
  }
  return htmlResponse(
    errorPage("Dienst vorübergehend nicht verfügbar", "Bitte versuchen Sie es später erneut."),
    500,
  );
}

export function createOAuthRouter(dependencies: OAuthRouterDependencies = {}) {
  const fetchFn = dependencies.fetchFn ?? fetch;

  async function authorize(request: Request, env: Cloudflare.Env): Promise<Response> {
    const oauth = authorizationServer.getOAuthApi(env);
    if (request.method === "GET") {
      const authRequest = await oauth.parseAuthRequest(request);
      if (authRequest.scope.length !== 1 || authRequest.scope[0] !== READ_SCOPE) {
        return redirectResponse(authorizationErrorRedirect(authRequest, "invalid_scope"));
      }
      const details = await oauth.describeConsent(authRequest);
      const transaction = await oauth.beginConsent(authRequest);
      return htmlResponse(consentPage(details, transaction.handle), 200, transaction.headers);
    }
    if (request.method !== "POST") {
      return new Response(null, { status: 405, headers: { allow: "GET, POST" } });
    }

    let body: ArrayBuffer;
    try {
      body = await readBodyWithLimit(request, 16_384);
    } catch (error) {
      if (!(error instanceof BodyTooLargeError)) throw error;
      return htmlResponse(errorPage("Ungültige Anfrage", GENERIC_INVALID_REQUEST), 413);
    }
    const boundedRequest = new Request(request.url, {
      method: request.method,
      headers: request.headers,
      body,
    });
    const form = await boundedRequest.formData();
    const handleValue = form.get("handle");
    const handle = typeof handleValue === "string" ? handleValue : "";
    if (handle.length === 0 || handle.length > 1_024) {
      return htmlResponse(errorPage("Ungültige Anfrage", GENERIC_INVALID_REQUEST), 400);
    }
    if (form.get("decision") !== "approve") {
      const denied = await oauth.denyConsent(request, handle);
      return redirectResponse(denied.redirectTo, denied.headers);
    }
    const selectedScopes = form.getAll("scope").filter((value): value is string => typeof value === "string");
    if (selectedScopes.length !== 1 || selectedScopes[0] !== READ_SCOPE) {
      return htmlResponse(errorPage("Berechtigung erforderlich", GENERIC_INVALID_REQUEST), 400);
    }

    const approved = await oauth.approveConsent(request, handle, { scope: [READ_SCOPE] });
    const upstreamPkce = await createPkcePair();
    const upstreamNonce = (await createPkcePair()).verifier;
    const upstream = await oauth.beginUpstream(approved.request, {
      data: { codeVerifier: upstreamPkce.verifier, nonce: upstreamNonce } satisfies UpstreamState,
      headers: approved.headers,
    });
    const location = await buildGoogleAuthorizationUrl({
      clientId: env.GOOGLE_CLIENT_ID,
      redirectUri: GOOGLE_CALLBACK_URL,
      state: upstream.state,
      nonce: upstreamNonce,
      codeVerifier: upstreamPkce.verifier,
    });
    return htmlResponse(googleTransitionPage(location.toString()), 200, upstream.headers);
  }

  async function callback(request: Request, env: Cloudflare.Env): Promise<Response> {
    if (request.method !== "GET") {
      return new Response(null, { status: 405, headers: { allow: "GET" } });
    }
    const oauth = authorizationServer.getOAuthApi(env);
    const resumed = await oauth.finishUpstream<UpstreamState>(request);
    const callbackUrl = new URL(request.url);
    if (callbackUrl.searchParams.has("error")) {
      return redirectResponse(
        authorizationErrorRedirect(resumed.request, "access_denied"),
        resumed.headers,
      );
    }
    const code = callbackUrl.searchParams.get("code");
    if (!code || code.length > 4_096) {
      return redirectResponse(
        authorizationErrorRedirect(resumed.request, "invalid_request"),
        resumed.headers,
      );
    }

    const { idToken } = await exchangeGoogleCode(
      {
        clientId: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        redirectUri: GOOGLE_CALLBACK_URL,
        code,
        codeVerifier: resumed.data.codeVerifier,
      },
      fetchFn,
    );
    const identity = await verifyGoogleIdToken(idToken, {
      clientId: env.GOOGLE_CLIENT_ID,
      expectedNonce: resumed.data.nonce,
      allowedEmail: ALLOWED_ADMIN_EMAIL,
      ...(dependencies.keyResolver ? { keyResolver: dependencies.keyResolver } : {}),
    });
    const { redirectTo } = await oauth.completeAuthorization({
      request: resumed.request,
      userId: identity.userId,
      metadata: {},
      scope: [READ_SCOPE],
      props: {
        googleSub: identity.sub,
        email: identity.email,
        emailVerified: true,
        role: "admin",
      } satisfies AdminAuthorizationProps,
    });
    return redirectResponse(redirectTo, resumed.headers);
  }

  return {
    async fetch(
      request: Request,
      env: Cloudflare.Env,
      ctx: ExecutionContext,
    ): Promise<Response> {
      try {
        const path = new URL(request.url).pathname;
        if (path === "/mcp/admin/authorize") return await authorize(request, env);
        if (path === "/mcp/admin/google/callback") return await callback(request, env);
        return await authorizationServer.fetch(request, env, ctx);
      } catch (error) {
        return safeErrorResponse(error);
      }
    },
  };
}
