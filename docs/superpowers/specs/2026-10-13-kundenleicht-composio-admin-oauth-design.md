# Kundenleicht Composio Admin MCP — Security Design

**Status:** Approved by Hannes Graf on 2026-10-13

## Goal

Expose a read-only Composio administration MCP at
`https://kundenleicht.at/mcp/admin` that ChatGPT can authenticate to using
OAuth 2.1. Google is the upstream identity provider and only the verified
Google account `hannes4723@gmail.com` may receive downstream access tokens.

The existing W3C validator Worker and its `kundenleicht.at/mcp*` route must
remain operational and unchanged.

## Existing infrastructure

- Cloudflare account: `a8480aea03724313f74dd27908080551`
- Zone `kundenleicht.at`: `b23bfec4dde5320c98b8984f713fd9eb`
- Admin Worker: `kundenleicht-composio-admin`
- Existing W3C Worker: `kundenleicht-mcp`
- OAuth KV: `kundenleicht-composio-oauth`
  (`d9672d8930464f0ea085b539a8b51ac5`)
- Existing secrets on the admin Worker, preserved by name and never read:
  `COMPOSIO_API_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- Existing W3C route: `kundenleicht.at/mcp*` -> `kundenleicht-mcp`

## Architecture

The existing `kundenleicht-composio-admin` Worker hosts both halves of the
split API from `@cloudflare/workers-oauth-provider` 1.x:

1. **Authorization server** with issuer
   `https://kundenleicht.at/mcp/admin`.
2. **Resource server** protecting the stateless MCP endpoint at the same
   canonical resource URL.

The resource server validates tokens directly against the co-located
authorization server. No public introspection endpoint or shared bearer
secret is introduced.

Google OpenID Connect is the upstream identity provider. The downstream
OAuth token is a Cloudflare-issued, resource-bound token; Google access or
refresh tokens are never returned to ChatGPT and are not retained after the
callback completes.

## OAuth endpoints

- MCP resource: `https://kundenleicht.at/mcp/admin`
- Authorization: `https://kundenleicht.at/mcp/admin/authorize`
- Token: `https://kundenleicht.at/mcp/admin/oauth/token`
- Dynamic registration: `https://kundenleicht.at/mcp/admin/oauth/register`
- Google callback: `https://kundenleicht.at/mcp/admin/google/callback`
- Protected-resource metadata:
  `https://kundenleicht.at/.well-known/oauth-protected-resource/mcp/admin`
- Authorization-server metadata:
  `https://kundenleicht.at/.well-known/oauth-authorization-server/mcp/admin`

Exact route handling is verified against the installed provider version
before deployment. The Worker receives only the specific `/mcp/admin*` and
well-known paths; the existing broad `/mcp*` route is not edited.

## Authentication and authorization flow

1. An unauthenticated MCP request receives `401` and a `WWW-Authenticate`
   challenge pointing to protected-resource metadata.
2. ChatGPT discovers the authorization server and uses OAuth authorization
   code flow with PKCE `S256` and an explicit `resource` parameter.
3. The authorization server validates the client metadata/registration,
   redirect URI, resource, scope, and PKCE request.
4. Before redirecting to Google, the provider creates a single-use,
   browser-bound upstream state. The Google request also includes upstream
   PKCE and an OIDC nonce.
5. The callback consumes the state once, exchanges the Google code, and
   verifies the ID token signature through Google's JWKS plus `iss`, `aud`,
   `exp`, `iat`, and `nonce`.
6. The callback requires `email_verified=true` and a case-normalized exact
   match for `hannes4723@gmail.com`. Every other identity is rejected before
   a downstream authorization code is issued.
7. The stable Google `sub`, allowed email, approved client identity, scopes,
   and resource are stored as encrypted authorization properties by the
   provider. Raw Google tokens are discarded.
8. Every MCP request verifies token activity, expiry, resource audience,
   required scope, and administrator identity properties.

OAuth provider state and tokens are stored only in `OAUTH_KV`. The library
stores authorization codes/tokens hashed and encrypts authorization
properties. Responses use `Cache-Control: no-store`; consent/callback pages
also use frame-denial and restrictive security headers.

## Downstream scopes and tools

Initial scope: `composio:read`.

Initial tools:

- `admin_profile`: stable opaque administrator identity for ChatGPT account
  linking; never returns a Google token.
- `composio_connection_check`: tests the API key with a minimal read request.
- `composio_list_toolkits`: cursor-based read-only toolkit listing.
- `composio_get_toolkit`: fetches public toolkit metadata by validated slug.
- `composio_list_connections`: returns a strict allow-list of connection
  metadata and status fields.

Composio responses are parsed and projected into safe schemas. In particular,
connected-account state, OAuth tokens, proxy credentials, headers, API keys,
and arbitrary provider payloads are never returned or logged.

There are no write tools in this release. Later write operations require a
separate `composio:write` scope, explicit per-tool authorization, structured
confirmation, audit events, and Hannes's approval for actions affecting users,
connections, permissions, or cost.

## Cloudflare routing and preservation

Add only these higher-specificity routes to the admin Worker:

- `kundenleicht.at/mcp/admin*`
- `kundenleicht.at/.well-known/oauth-protected-resource/mcp/admin*`
- `kundenleicht.at/.well-known/oauth-authorization-server/mcp/admin*`

Do not modify or redeploy `kundenleicht-mcp`. Smoke-test
`https://kundenleicht.at/mcp/health` and an authenticated W3C MCP request
before and after routing changes. The pre-change W3C version and route ID are
recorded in the backup manifest.

## Error and log policy

- Public errors contain stable codes and generic messages only.
- OAuth codes, access/refresh tokens, Google tokens, PKCE verifiers, client
  secrets, the Composio key, and authorization headers are never logged.
- Query-string logging is disabled/redacted because OAuth callbacks contain
  codes and state.
- Upstream error bodies are not proxied to clients.
- Composio calls use bounded timeouts and return sanitized failure classes.
- Security headers and no-store caching apply to all auth responses.

## Verification gates

The release may be routed only after automated tests cover:

- missing, malformed, invalid, expired, wrong-resource, and insufficient-scope
  access tokens;
- disallowed/unverified Google identities;
- state replay/tampering, nonce mismatch, and PKCE mismatch;
- redirect/resource validation and discovery metadata;
- absence of token/secret material from logs and error responses;
- strict Composio response projection;
- MCP initialization/tool discovery/tool calls;
- unchanged W3C route, Worker version, and live behavior.

The final gate is an interactive Google login followed by a real authenticated
Composio read and successful ChatGPT connector use.

