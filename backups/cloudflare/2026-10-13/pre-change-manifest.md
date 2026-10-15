# Cloudflare pre-change manifest — 2026-10-13

Captured before any code, binding, deployment, or route change.

## Kundenleicht Composio Admin

- Worker: `kundenleicht-composio-admin`
- Deployment ID: `5413bdad-581e-4f4a-8847-fb58e1693d1c`
- Version ID: `ea164876-49a1-4911-a897-4f7ddf35c09e`
- Compatibility date: unset
- Secret binding names observed, values never read:
  `COMPOSIO_API_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- KV binding before change: none
- Existing code backup:
  `backups/cloudflare/2026-10-13/kundenleicht-composio-admin.js`

Cloudflare retains the immutable version above for rollback.

## Existing W3C MCP

- Worker: `kundenleicht-mcp`
- Deployment ID: `eea06a13-b4a6-4cac-8db9-098d4f6c313c`
- Version ID: `40cf6ce2-41b7-41f8-8eff-f3059b300b6e`
- Compatibility date: `2026-10-08`
- KV binding: `CUSTOMER_CONFIG` ->
  `fe8b2e6122d64f61943612d6bb01d686`
- Route ID: `b853a4933f8d45a1aa20d8b76a51b127`
- Route: `kundenleicht.at/mcp*` -> `kundenleicht-mcp`
- Existing source backup already retained in ChatGPT Library as
  `kundenleicht-w3c-mcp.zip` and in the immutable Worker version above.

The W3C Worker is outside deployment scope and must not be uploaded or edited.

## OAuth storage and zone

- Account ID: `a8480aea03724313f74dd27908080551`
- Zone ID: `b23bfec4dde5320c98b8984f713fd9eb`
- KV namespace: `kundenleicht-composio-oauth`
- KV namespace ID: `d9672d8930464f0ea085b539a8b51ac5`

## Rollback

If the admin deployment fails before routes are added, deploy version
`ea164876-49a1-4911-a897-4f7ddf35c09e` to
`kundenleicht-composio-admin`. If a route change fails, remove only the newly
created route IDs and leave `b853a4933f8d45a1aa20d8b76a51b127`
unchanged. No W3C rollback should be necessary because that Worker is never
deployed by this plan.

