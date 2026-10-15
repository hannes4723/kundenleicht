# Kundenleicht Composio Admin Worker

This Cloudflare Worker exposes a read-only, Google-authenticated Composio MCP
for the single approved Kundenleicht administrator. It contains an OAuth 2.1
authorization server and a protected stateless MCP resource server.

## Public endpoints

| Purpose | URL |
| --- | --- |
| MCP resource | `https://kundenleicht.at/mcp/admin` |
| Authorization | `https://kundenleicht.at/mcp/admin/authorize` |
| Token | `https://kundenleicht.at/mcp/admin/oauth/token` |
| Dynamic registration | `https://kundenleicht.at/mcp/admin/oauth/register` |
| Google callback | `https://kundenleicht.at/mcp/admin/google/callback` |
| Authorization-server metadata | `https://kundenleicht.at/.well-known/oauth-authorization-server/mcp/admin` |
| Protected-resource metadata | `https://kundenleicht.at/.well-known/oauth-protected-resource/mcp/admin` |
| Health | `https://kundenleicht.at/mcp/admin/health` |

ChatGPT should be configured with the MCP resource URL only. It discovers the
remaining endpoints through the two OAuth metadata documents.

## Authorization model

- Google OIDC verifies signature, issuer, audience, expiry, issued-at time,
  nonce, verified email, and stable Google subject.
- Only `hannes4723@gmail.com` is accepted.
- The downstream token is bound to resource
  `https://kundenleicht.at/mcp/admin` and scope `composio:read`.
- Public authorization/token traffic is limited to 60 requests per minute per
  source and dynamic client registration to 10 requests per minute per source
  and Cloudflare location.
- Google tokens are discarded after identity verification. Composio credentials
  and provider state never enter MCP responses.
- Authorization codes, state, token material, and API credentials are never
  logged. Cloudflare query strings are redacted.

## Read-only tools

- `admin_profile`
- `composio_connection_check`
- `composio_list_toolkits`
- `composio_get_toolkit`
- `composio_list_connections`

No Composio write endpoint is reachable through this Worker. A future write
release must use a separate `composio:write` scope, explicit per-tool checks,
structured confirmation, audit events, and administrator approval for changes
to users, connections, permissions, or costs.

## Verify locally

```sh
npm ci
npm run check
npm run smoke:local
npm audit --audit-level=high
```

The build scanner rejects bundled test credentials, private keys, application
logging calls, disabled query redaction, and route declarations in the Worker
configuration. `smoke:local` sends OAuth discovery, anonymous access, MCP
initialize, tool-list, and tool-call requests through Cloudflare's official
Miniflare-backed test runtime.

## Cloudflare bindings

The deployment requires the existing secret bindings `COMPOSIO_API_KEY`,
`GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET`, the `OAUTH_KV` KV binding, and
the two configured native rate-limit bindings. Never export secret values.
Confirm bindings by name and type only.

Production route changes are deliberately kept out of `wrangler.jsonc`. Add or
manage only these three specific routes outside the code deployment:

- `kundenleicht.at/mcp/admin*`
- `kundenleicht.at/.well-known/oauth-protected-resource/mcp/admin*`
- `kundenleicht.at/.well-known/oauth-authorization-server/mcp/admin*`

Do not edit the existing `kundenleicht.at/mcp*` route or deploy the
`kundenleicht-mcp` Worker.

## Rollback

Remove the three admin-specific routes first, then roll
`kundenleicht-composio-admin` back to its recorded pre-change version. The W3C
Worker and its route are independent and must remain untouched. OAuth records
in KV can remain in place; without the admin routes they are not reachable.
