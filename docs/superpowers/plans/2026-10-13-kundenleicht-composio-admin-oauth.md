# Kundenleicht Composio Admin OAuth Implementation Plan

**Spec:** `docs/superpowers/specs/2026-10-13-kundenleicht-composio-admin-oauth-design.md`

**Goal:** Implement, verify, deploy, and connect a Google-authenticated,
read-only Composio administration MCP without changing the existing W3C
Worker.

**Global constraints:** Never read, print, replace, or delete secret values.
Preserve secret bindings during deployment. Never log authorization material.
Do not modify or deploy `kundenleicht-mcp`. Use test-first development for all
production behavior. Production routes are the final infrastructure change,
after local verification and an unrouted admin-Worker deployment.

## Task 1: Repository, backup, and test harness

**Files:**

- Create `workers/composio-admin/package.json`
- Create `workers/composio-admin/tsconfig.json`
- Create `workers/composio-admin/wrangler.jsonc`
- Create `workers/composio-admin/vitest.config.ts`
- Create `workers/composio-admin/test/env.d.ts`
- Create `backups/cloudflare/2026-10-13/pre-change-manifest.md`
- Create `backups/cloudflare/2026-10-13/kundenleicht-composio-admin.js`

Steps:

1. Record immutable deployment/version IDs, binding names, KV namespace ID,
   and existing route IDs without secret values.
2. Save the existing admin source. Reference the immutable W3C deployment and
   existing Library source backup instead of repackaging secrets or metadata.
3. Pin current compatible versions of the official OAuth/MCP libraries and
   local test tooling.
4. Configure Workers Vitest with an in-memory `OAUTH_KV` and non-secret test
   values.
5. Run the empty baseline suite and typecheck.
6. Commit: `chore: scaffold composio admin worker and backups`.

**Expected:** baseline commands succeed; no secret values exist in git.

## Task 2: Security primitives and Google OIDC

**Files:**

- Create `workers/composio-admin/src/security.ts`
- Create `workers/composio-admin/src/google.ts`
- Create `workers/composio-admin/test/google.test.ts`
- Create `workers/composio-admin/test/security.test.ts`

Steps:

1. RED: tests for exact allow-listed verified email, stable `sub`, issuer,
   audience, expiry, nonce, malformed token, safe error mapping, and secret
   redaction.
2. GREEN: implement OIDC authorization URL creation with upstream PKCE/nonce,
   code exchange, Google JWKS verification, and identity projection.
3. RED: tests for state replay/tamper and browser-binding failure through the
   provider helper boundary.
4. GREEN: implement single-use upstream state consumption and hardened auth
   response headers.
5. Run targeted tests, full suite, and typecheck.
6. Commit: `feat: verify allow-listed Google administrator`.

**Expected:** each test is observed failing before implementation and passing
afterward; errors contain no code, token, verifier, nonce, or secret value.

## Task 3: Safe Composio read client

**Files:**

- Create `workers/composio-admin/src/composio.ts`
- Create `workers/composio-admin/test/composio.test.ts`

Steps:

1. RED: tests for connection check, toolkit pagination/search, slug
   validation, toolkit retrieval, connected-account filters, timeouts, error
   sanitization, and response-field allow-listing.
2. GREEN: implement the v3.1 client with injected fetch, bounded timeouts,
   strict input limits, and projection schemas.
3. Prove fixtures containing OAuth tokens, API keys, proxy passwords, headers,
   and nested provider state cannot appear in returned structures or logs.
4. Run targeted tests, full suite, and typecheck.
5. Commit: `feat: add sanitized composio read client`.

**Expected:** only documented safe fields leave the client.

## Task 4: OAuth authorization server

**Files:**

- Create `workers/composio-admin/src/oauth.ts`
- Create `workers/composio-admin/src/pages.ts`
- Create `workers/composio-admin/test/oauth.test.ts`

Steps:

1. RED: integration tests for OAuth server metadata, DCR/CIMD support,
   redirect/resource/scope validation, consent CSRF, downstream PKCE S256,
   upstream state, callback identity rejection, authorization code replay,
   refresh handling, and token expiry.
2. GREEN: configure `OAuthAuthorizationServer` using `OAUTH_KV`, exact issuer
   and resource URLs, short authorization-code lifetime, bounded access-token
   lifetime, refresh rotation, `composio:read`, and Google handlers.
3. Add minimal consent/denial pages with CSP, frame denial, no-referrer, and
   no-store headers.
4. Run targeted tests, full suite, and typecheck.
5. Commit: `feat: add google-backed oauth authorization server`.

**Expected:** OAuth 2.1 metadata advertises S256 and the path-based issuer;
state/code/verifier misuse is rejected.

## Task 5: MCP resource server and tools

**Files:**

- Create `workers/composio-admin/src/mcp.ts`
- Create `workers/composio-admin/src/index.ts`
- Create `workers/composio-admin/test/mcp.test.ts`
- Create `workers/composio-admin/test/worker.test.ts`

Steps:

1. RED: tests for protected-resource metadata and `401` challenge; invalid,
   expired, wrong-resource, wrong-identity, and insufficient-scope tokens; MCP
   initialize/list/call; safe tool outputs; unknown tools; and method limits.
2. GREEN: configure `OAuthResourceServer`, direct token validation, stateless
   MCP transport, per-tool `composio:read` authorization, and the five approved
   read-only tools.
3. Add request IDs, no-store/security headers, body-size limits, and generic
   uncaught-error handling without secret logging.
4. Prove the public route contains no write-capable Composio operation.
5. Run targeted tests, full suite, typecheck, and lint.
6. Commit: `feat: expose protected read-only composio mcp`.

**Expected:** anonymous/invalid calls fail closed and authenticated calls return
only safe MCP results.

## Task 6: Local protocol and security verification

**Files:**

- Create `workers/composio-admin/test/security-regression.test.ts`
- Create `workers/composio-admin/scripts/check-bundle.mjs`
- Create `workers/composio-admin/README.md`

Steps:

1. RED: add regression tests for all security acceptance criteria not already
   covered, including log-capture assertions and bundle scans.
2. GREEN: close only evidenced gaps.
3. Run the full unit/integration suite, typecheck, lint, production build,
   dependency audit, and bundle secret/log scan.
4. Run a local MCP protocol smoke test against Wrangler/Miniflare.
5. Document deployment, rollback, endpoints, scopes, and future write-control
   architecture.
6. Commit: `test: complete oauth and mcp security verification`.

**Expected:** clean commands with no unresolved high/critical dependency
findings and no authorization material in build output/logging statements.

## Task 7: Safe Cloudflare deployment and routing

**Files:**

- Update `backups/cloudflare/2026-10-13/pre-change-manifest.md` with deployment
  evidence only; never secret values.
- Create `docs/deployment/2026-10-13-composio-admin-verification.md`.

Steps:

1. Record pre-change live W3C health, authenticated MCP smoke result, Worker
   version IDs, and route inventory.
2. Upload the bundled admin Worker while preserving existing `secret_text`
   bindings and adding only `OAUTH_KV`; enable `nodejs_compat`,
   `global_fetch_strictly_public`, and query-string redaction.
3. Verify the deployed Worker version and bindings by names/types only.
4. Add the three exact higher-specificity routes; do not edit the existing
   `/mcp*` route.
5. Verify both discovery documents, anonymous/invalid-token failures, security
   headers, and admin health.
6. Re-run the unchanged W3C live smoke tests and compare version/route IDs.
7. Commit deployment evidence: `docs: record composio admin deployment`.

**Expected:** W3C behavior/version/route unchanged; admin OAuth discovery and
resource challenge live; existing secrets preserved by name/type.

## Task 8: Interactive and real-service end-to-end tests

**Files:**

- Update `docs/deployment/2026-10-13-composio-admin-verification.md`

Steps:

1. Start a real OAuth authorization using a production-equivalent registered
   client and PKCE, then ask Hannes only to approve the Google screen.
2. Exchange the code, call MCP initialize/tools/list, run
   `composio_connection_check`, list one toolkit, and list sanitized connection
   status.
3. Connect the MCP in ChatGPT and verify the stable account identity plus one
   real read-only Composio tool call.
4. Record pass/fail evidence without tokens, codes, personal connection data,
   or secrets.
5. Commit: `docs: record oauth and composio end-to-end tests`.

**Expected:** the approved Google administrator succeeds; wrong identity and
all invalid-token cases fail; ChatGPT uses the connector; at least one real
Composio read succeeds.

## Review focus

Review token audience/resource binding, client redirect handling, state and
nonce lifetime/replay, downstream and upstream PKCE separation, authorization
property trust boundaries, email/sub semantics, refresh-token behavior,
Cloudflare route precedence, Composio response projection, sensitive logging,
and preservation of the W3C worker and existing secret bindings.

