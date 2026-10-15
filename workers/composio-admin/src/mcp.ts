import {
  OAuthResourceServer,
  insufficientScope,
  type OAuthResourceContext,
  type OAuthResourceTokenValidator,
} from "@cloudflare/workers-oauth-provider";
import { McpServer, requireScopes } from "@modelcontextprotocol/server";
import { createMcpHandler, getMcpAuthContext } from "agents/mcp/server";
import { z } from "zod";
import { ComposioError, createComposioClient } from "./composio";
import {
  ALLOWED_ADMIN_EMAIL,
  AUTHORIZATION_SERVER_ISSUER,
  MCP_RESOURCE,
  READ_SCOPE,
  authorizationServer,
  type AdminAuthorizationProps,
} from "./oauth";
import { BodyTooLargeError, publicJsonError, readBodyWithLimit } from "./security";

const SERVER_NAME = "kundenleicht-composio-admin";
const SERVER_VERSION = "1.0.0";
const TOOL_SECURITY = [{ type: "oauth2", scopes: [READ_SCOPE] }] as const;

const toolkitCategorySchema = z.object({
  slug: z.string(),
  name: z.string(),
});

const toolkitSchema = z.object({
  slug: z.string(),
  name: z.string(),
  description: z.string().optional(),
  logoUrl: z.string().optional(),
  appUrl: z.string().optional(),
  authSchemes: z.array(z.string()),
  categories: z.array(toolkitCategorySchema),
  toolsCount: z.number().int().nonnegative().optional(),
  triggersCount: z.number().int().nonnegative().optional(),
  availableVersions: z.array(z.string()).optional(),
});

const connectionSchema = z.object({
  id: z.string(),
  toolkitSlug: z.string(),
  authConfigId: z.string().optional(),
  authScheme: z.string().optional(),
  isComposioManaged: z.boolean().optional(),
  alias: z.string().optional(),
  userId: z.string().optional(),
  status: z.string(),
  isDisabled: z.boolean(),
  accountType: z.string().optional(),
  createdAt: z.string().optional(),
  updatedAt: z.string().optional(),
});

function readOnlyConfig(openWorld = true) {
  return {
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: openWorld,
    },
    scopeChallenge: requireScopes(READ_SCOPE),
    _meta: { securitySchemes: TOOL_SECURITY },
  };
}

function toolResult<T extends object>(data: T, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data) }],
    structuredContent: { ...data },
    ...(isError ? { isError: true } : {}),
  };
}

function composioFailure(error: unknown) {
  const code = error instanceof ComposioError ? error.code : "upstream_unavailable";
  return {
    content: [
      {
        type: "text" as const,
        text: `Die Composio-Abfrage konnte nicht sicher abgeschlossen werden (${code}).`,
      },
    ],
    isError: true,
  };
}

function verifiedAdminProps(): AdminAuthorizationProps {
  const props = getMcpAuthContext()?.props;
  if (
    props?.role !== "admin" ||
    props.emailVerified !== true ||
    props.email !== ALLOWED_ADMIN_EMAIL ||
    typeof props.googleSub !== "string" ||
    !/^[0-9]{1,64}$/u.test(props.googleSub)
  ) {
    throw new Error("Verified administrator context required");
  }
  return {
    googleSub: props.googleSub,
    email: props.email,
    emailVerified: true,
    role: "admin",
  };
}

export function createAdminMcpServer(env: Cloudflare.Env, fetchFn: typeof fetch = fetch) {
  const composio = createComposioClient({ apiKey: env.COMPOSIO_API_KEY, fetchFn });
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });

  server.registerTool(
    "admin_profile",
    {
      title: "Kundenleicht administrator profile",
      description: "Returns the stable identity of the authenticated Kundenleicht administrator.",
      inputSchema: z.object({}).strict(),
      outputSchema: z.object({
        id: z.string(),
        role: z.literal("admin"),
      }),
      ...readOnlyConfig(false),
    },
    () => {
      verifiedAdminProps();
      return toolResult({
        id: "kundenleicht-admin",
        role: "admin" as const,
      });
    },
  );

  server.registerTool(
    "composio_connection_check",
    {
      title: "Check Composio connection",
      description: "Performs a minimal read-only request to verify Composio API authentication.",
      inputSchema: z.object({}).strict(),
      outputSchema: z.object({
        authenticated: z.boolean(),
        httpStatus: z.number().int(),
      }),
      ...readOnlyConfig(),
    },
    async () => {
      verifiedAdminProps();
      try {
        const result = await composio.connectionCheck();
        return toolResult(result, !result.authenticated);
      } catch (error) {
        return composioFailure(error);
      }
    },
  );

  server.registerTool(
    "composio_list_toolkits",
    {
      title: "List Composio toolkits",
      description: "Lists sanitized public metadata for available Composio toolkits.",
      inputSchema: z
        .object({
          limit: z.number().int().min(1).max(100).optional(),
          search: z.string().min(1).max(100).optional(),
          cursor: z.string().min(1).max(2_048).optional(),
        })
        .strict(),
      outputSchema: z.object({
        items: z.array(toolkitSchema),
        nextCursor: z.string().optional(),
      }),
      ...readOnlyConfig(),
    },
    async (input) => {
      verifiedAdminProps();
      try {
        return toolResult(
          await composio.listToolkits({
            ...(input.limit === undefined ? {} : { limit: input.limit }),
            ...(input.search === undefined ? {} : { search: input.search }),
            ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
          }),
        );
      } catch (error) {
        return composioFailure(error);
      }
    },
  );

  server.registerTool(
    "composio_get_toolkit",
    {
      title: "Get Composio toolkit",
      description: "Returns sanitized metadata for one Composio toolkit by slug.",
      inputSchema: z.object({ slug: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,99}$/u) }).strict(),
      outputSchema: toolkitSchema,
      ...readOnlyConfig(),
    },
    async ({ slug }) => {
      verifiedAdminProps();
      try {
        return toolResult(await composio.getToolkit(slug));
      } catch (error) {
        return composioFailure(error);
      }
    },
  );

  server.registerTool(
    "composio_list_connections",
    {
      title: "List Composio connection status",
      description:
        "Lists sanitized Composio connected-account status. Credentials, provider state and tokens are always omitted.",
      inputSchema: z
        .object({
          limit: z.number().int().min(1).max(100).optional(),
          toolkitSlugs: z.array(z.string().regex(/^[a-z0-9][a-z0-9_-]{0,99}$/u)).max(20).optional(),
          statuses: z
            .array(
              z.enum([
                "INITIALIZING",
                "INITIATED",
                "ACTIVE",
                "FAILED",
                "EXPIRED",
                "INACTIVE",
                "REVOKED",
              ]),
            )
            .max(20)
            .optional(),
          userIds: z.array(z.string().regex(/^[A-Za-z0-9._:@-]{1,200}$/u)).max(20).optional(),
          cursor: z.string().min(1).max(2_048).optional(),
        })
        .strict(),
      outputSchema: z.object({
        items: z.array(connectionSchema),
        nextCursor: z.string().optional(),
      }),
      ...readOnlyConfig(),
    },
    async (input) => {
      verifiedAdminProps();
      try {
        return toolResult(
          await composio.listConnections({
            ...(input.limit === undefined ? {} : { limit: input.limit }),
            ...(input.toolkitSlugs === undefined
              ? {}
              : { toolkitSlugs: input.toolkitSlugs }),
            ...(input.statuses === undefined ? {} : { statuses: input.statuses }),
            ...(input.userIds === undefined ? {} : { userIds: input.userIds }),
            ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
          }),
        );
      } catch (error) {
        return composioFailure(error);
      }
    },
  );

  return server;
}

export interface AdminResourceServerDependencies {
  fetchFn?: typeof fetch;
  validateToken?: (
    env: Cloudflare.Env,
    request: Request,
  ) => OAuthResourceTokenValidator<AdminAuthorizationProps>;
}

export function createAdminResourceServer(dependencies: AdminResourceServerDependencies = {}) {
  const fetchFn = dependencies.fetchFn ?? fetch;
  return new OAuthResourceServer<Cloudflare.Env, AdminAuthorizationProps>({
    resourceMetadata: {
      resource: MCP_RESOURCE,
      authorization_servers: [AUTHORIZATION_SERVER_ISSUER],
      bearer_methods_supported: ["header"],
      resource_name: "Kundenleicht Composio Administration",
    },
    requiredScopes: [READ_SCOPE],
    validateToken:
      dependencies.validateToken ??
      ((env) => (resource, token) =>
        authorizationServer.validateToken<AdminAuthorizationProps>(resource, token, env)),
    handler: {
      async fetch(
        request: Request,
        env: Cloudflare.Env,
        ctx: OAuthResourceContext<AdminAuthorizationProps>,
      ): Promise<Response> {
        const props = ctx.props;
        if (
          props.role !== "admin" ||
          props.emailVerified !== true ||
          props.email !== ALLOWED_ADMIN_EMAIL ||
          !/^[0-9]{1,64}$/u.test(props.googleSub) ||
          ctx.auth.userId !== `google-${props.googleSub}`
        ) {
          return publicJsonError("forbidden", 403);
        }
        if (!ctx.auth.scope.includes(READ_SCOPE)) {
          return insufficientScope(ctx.auth, [READ_SCOPE]);
        }

        let boundedRequest = request;
        if (request.method === "POST") {
          let body: ArrayBuffer;
          try {
            body = await readBodyWithLimit(request, 262_144);
          } catch (error) {
            if (error instanceof BodyTooLargeError) {
              return publicJsonError("request_too_large", 413);
            }
            throw error;
          }
          boundedRequest = new Request(request.url, {
            method: request.method,
            headers: request.headers,
            body,
          });
        }
        const handler = createMcpHandler(
          () => createAdminMcpServer(env, fetchFn),
          {
            route: "/mcp/admin",
            responseMode: "json",
            legacy: "stateless",
            corsOptions: {
              origin: "https://chatgpt.com",
              methods: "POST, OPTIONS",
              headers: "authorization, content-type, mcp-protocol-version, mcp-session-id",
            },
            allowedHostnames: ["kundenleicht.at", "localhost", "127.0.0.1"],
            allowedOriginHostnames: [
              "chatgpt.com",
              "chat.openai.com",
              "kundenleicht.at",
              "localhost",
              "127.0.0.1",
            ],
          },
        );
        const response = await handler(boundedRequest, env, ctx);
        response.headers.set("cache-control", "no-store");
        response.headers.set("x-content-type-options", "nosniff");
        return response;
      },
    },
  });
}

export const adminResourceServer = createAdminResourceServer();
