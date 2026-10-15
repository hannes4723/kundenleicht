import { adminResourceServer } from "./mcp";
import { createOAuthRouter } from "./oauth";
import { publicJsonError } from "./security";

const oauthRouter = createOAuthRouter();
const AUTHORIZATION_METADATA_PATH =
  "/.well-known/oauth-authorization-server/mcp/admin";
const RESOURCE_METADATA_PATH =
  "/.well-known/oauth-protected-resource/mcp/admin";

function rateLimitKey(request: Request): string {
  const value = request.headers.get("cf-connecting-ip") ?? "unknown";
  return /^[0-9A-Fa-f:.]{2,64}$/u.test(value) ? value : "unknown";
}

async function enforceOAuthRateLimit(
  request: Request,
  env: Cloudflare.Env,
  path: string,
): Promise<Response | undefined> {
  let limiter: RateLimit | undefined;
  if (request.method === "POST" && path === "/mcp/admin/oauth/register") {
    limiter = env.DCR_RATE_LIMITER;
  } else if (
    path === "/mcp/admin/authorize" ||
    (request.method === "POST" && path === "/mcp/admin/oauth/token")
  ) {
    limiter = env.OAUTH_RATE_LIMITER;
  }
  if (!limiter) return undefined;

  let outcome: RateLimitOutcome;
  try {
    outcome = await limiter.limit({ key: `${path}:${rateLimitKey(request)}` });
  } catch {
    return publicJsonError("service_unavailable", 503);
  }
  if (outcome.success) return undefined;
  const response = publicJsonError("rate_limited", 429);
  response.headers.set("retry-after", "60");
  return response;
}

function withCommonHeaders(response: Response, requestId: string): Response {
  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.set("referrer-policy", "no-referrer");
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-request-id", requestId);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function route(
  request: Request,
  env: Cloudflare.Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const path = new URL(request.url).pathname;
  const rateLimited = await enforceOAuthRateLimit(request, env, path);
  if (rateLimited) return rateLimited;

  if (path === "/mcp/admin/health") {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response(null, { status: 405, headers: { allow: "GET, HEAD" } });
    }
    return Response.json({
      ok: true,
      service: "kundenleicht-composio-admin",
      authentication: "oauth2",
    });
  }

  if (path === AUTHORIZATION_METADATA_PATH) {
    return oauthRouter.fetch(request, env, ctx);
  }
  if (path === RESOURCE_METADATA_PATH) {
    return adminResourceServer.fetch(request, env, ctx);
  }

  if (
    path === "/mcp/admin/authorize" ||
    path === "/mcp/admin/google/callback" ||
    path.startsWith("/mcp/admin/oauth/")
  ) {
    return oauthRouter.fetch(request, env, ctx);
  }

  if (path === "/mcp/admin" || path === "/mcp/admin/") {
    return adminResourceServer.fetch(request, env, ctx);
  }

  return publicJsonError("not_found", 404);
}

export default {
  async fetch(
    request: Request,
    env: Cloudflare.Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const requestId = crypto.randomUUID();
    try {
      return withCommonHeaders(await route(request, env, ctx), requestId);
    } catch {
      return withCommonHeaders(publicJsonError("internal_error", 500), requestId);
    }
  },
} satisfies ExportedHandler<Cloudflare.Env>;
