const API_BASE = "https://backend.composio.dev/api/v3.1";
const MAX_RESPONSE_BYTES = 2_000_000;
const CONNECTION_STATUSES = new Set([
  "INITIALIZING",
  "INITIATED",
  "ACTIVE",
  "FAILED",
  "EXPIRED",
  "INACTIVE",
  "REVOKED",
]);

export type ComposioErrorCode =
  | "invalid_input"
  | "upstream_unavailable"
  | "upstream_rejected"
  | "invalid_response";

export class ComposioError extends Error {
  constructor(
    readonly code: ComposioErrorCode,
    readonly httpStatus?: number,
  ) {
    super(code);
    this.name = "ComposioError";
  }
}

export interface SafeToolkitCategory {
  slug: string;
  name: string;
}

export interface SafeToolkit {
  slug: string;
  name: string;
  description?: string;
  logoUrl?: string;
  appUrl?: string;
  authSchemes: string[];
  categories: SafeToolkitCategory[];
  toolsCount?: number;
  triggersCount?: number;
  availableVersions?: string[];
}

export interface SafeConnection {
  id: string;
  toolkitSlug: string;
  authConfigId?: string;
  authScheme?: string;
  isComposioManaged?: boolean;
  alias?: string;
  userId?: string;
  status: string;
  isDisabled: boolean;
  accountType?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ComposioClient {
  connectionCheck(): Promise<{ authenticated: boolean; httpStatus: number }>;
  listToolkits(options?: {
    limit?: number;
    search?: string;
    cursor?: string;
  }): Promise<{ items: SafeToolkit[]; nextCursor?: string }>;
  getToolkit(slug: string): Promise<SafeToolkit>;
  listConnections(options?: {
    limit?: number;
    toolkitSlugs?: string[];
    statuses?: string[];
    userIds?: string[];
    cursor?: string;
  }): Promise<{ items: SafeConnection[]; nextCursor?: string }>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function optionalString(value: unknown, maxLength = 500): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength
    ? value
    : undefined;
}

function optionalBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function optionalInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : undefined;
}

function optionalHttpsUrl(value: unknown): string | undefined {
  const raw = optionalString(value, 2_048);
  if (!raw) return undefined;
  try {
    const url = new URL(raw);
    return url.protocol === "https:" && !url.username && !url.password ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}

function safeStringArray(value: unknown, maximum = 20): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .slice(0, maximum)
    .map((item) => optionalString(item, 100))
    .filter((item): item is string => item !== undefined);
}

function projectToolkit(value: unknown): SafeToolkit {
  if (!isRecord(value)) throw new ComposioError("invalid_response");
  const slug = optionalString(value.slug, 100);
  const name = optionalString(value.name, 200);
  if (!slug || !name) throw new ComposioError("invalid_response");

  const meta = isRecord(value.meta) ? value.meta : {};
  const rawCategories = Array.isArray(meta.categories) ? meta.categories : [];
  const categories = rawCategories.slice(0, 30).flatMap((category) => {
    if (!isRecord(category)) return [];
    const categorySlug = optionalString(category.slug, 100) ?? optionalString(category.id, 100);
    const categoryName = optionalString(category.name, 200);
    return categorySlug && categoryName ? [{ slug: categorySlug, name: categoryName }] : [];
  });

  const description = optionalString(meta.description, 2_000);
  const logoUrl = optionalHttpsUrl(meta.logo);
  const appUrl = optionalHttpsUrl(meta.app_url);
  const toolsCount = optionalInteger(meta.tools_count);
  const triggersCount = optionalInteger(meta.triggers_count);
  const availableVersions = safeStringArray(meta.available_versions, 30);

  return {
    slug,
    name,
    authSchemes: safeStringArray(value.auth_schemes, 20),
    categories,
    ...(description ? { description } : {}),
    ...(logoUrl ? { logoUrl } : {}),
    ...(appUrl ? { appUrl } : {}),
    ...(toolsCount === undefined ? {} : { toolsCount }),
    ...(triggersCount === undefined ? {} : { triggersCount }),
    ...(availableVersions.length === 0 ? {} : { availableVersions }),
  };
}

function projectConnection(value: unknown): SafeConnection {
  if (!isRecord(value)) throw new ComposioError("invalid_response");
  const toolkit = isRecord(value.toolkit) ? value.toolkit : {};
  const authConfig = isRecord(value.auth_config) ? value.auth_config : {};
  const experimental = isRecord(value.experimental) ? value.experimental : {};
  const id = optionalString(value.id, 200);
  const toolkitSlug = optionalString(toolkit.slug, 100);
  const status = optionalString(value.status, 40);
  if (!id || !toolkitSlug || !status) throw new ComposioError("invalid_response");

  const authConfigId = optionalString(authConfig.id, 200);
  const authScheme = optionalString(authConfig.auth_scheme ?? value.authScheme, 50);
  const isComposioManaged = optionalBoolean(authConfig.is_composio_managed);
  const alias = optionalString(value.alias, 200);
  const userId = optionalString(value.user_id, 200);
  const accountType = optionalString(experimental.account_type, 40);
  const createdAt = optionalString(value.created_at, 64);
  const updatedAt = optionalString(value.updated_at, 64);

  return {
    id,
    toolkitSlug,
    status,
    isDisabled: optionalBoolean(value.is_disabled) ?? optionalBoolean(authConfig.is_disabled) ?? false,
    ...(authConfigId ? { authConfigId } : {}),
    ...(authScheme ? { authScheme } : {}),
    ...(isComposioManaged === undefined ? {} : { isComposioManaged }),
    ...(alias ? { alias } : {}),
    ...(userId ? { userId } : {}),
    ...(accountType ? { accountType } : {}),
    ...(createdAt ? { createdAt } : {}),
    ...(updatedAt ? { updatedAt } : {}),
  };
}

function validateLimit(limit: number | undefined, fallback: number): number {
  const value = limit ?? fallback;
  if (!Number.isInteger(value) || value < 1 || value > 100) {
    throw new ComposioError("invalid_input");
  }
  return value;
}

function validateOpaque(value: string | undefined, maximum: number): string | undefined {
  if (value === undefined) return undefined;
  const hasControlCharacter = Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
  if (value.length === 0 || value.length > maximum || hasControlCharacter) {
    throw new ComposioError("invalid_input");
  }
  return value;
}

function validateSlug(value: string): string {
  if (!/^[a-z0-9][a-z0-9_-]{0,99}$/u.test(value)) {
    throw new ComposioError("invalid_input");
  }
  return value;
}

function validateArray(
  values: string[] | undefined,
  validator: (value: string) => string,
): string[] {
  if (values === undefined) return [];
  if (values.length === 0 || values.length > 20) throw new ComposioError("invalid_input");
  return values.map(validator);
}

async function readBoundedResponse(response: Response): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let result = "";
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => undefined);
      throw new ComposioError("invalid_response");
    }
    result += decoder.decode(value, { stream: true });
  }
  return result + decoder.decode();
}

export function createComposioClient(options: {
  apiKey: string;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
}): ComposioClient {
  const fetchFn = options.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;

  async function request(
    path: string,
    parameters: Array<[string, string]>,
  ): Promise<{ payload: unknown; status: number }> {
    if (options.apiKey.length < 8 || options.apiKey.length > 1_024) {
      throw new ComposioError("invalid_input");
    }
    const url = new URL(`${API_BASE}${path}`);
    for (const [name, value] of parameters) url.searchParams.append(name, value);

    let response: Response;
    try {
      response = await fetchFn(url, {
        method: "GET",
        headers: { accept: "application/json", "x-api-key": options.apiKey },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      throw new ComposioError("upstream_unavailable");
    }

    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new ComposioError("upstream_rejected", response.status);
    }

    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
      await response.body?.cancel().catch(() => undefined);
      throw new ComposioError("invalid_response");
    }

    let text: string;
    try {
      text = await readBoundedResponse(response);
    } catch (error) {
      if (error instanceof ComposioError) throw error;
      throw new ComposioError("invalid_response");
    }

    try {
      return { payload: JSON.parse(text) as unknown, status: response.status };
    } catch {
      throw new ComposioError("invalid_response");
    }
  }

  return {
    async connectionCheck() {
      try {
        const { status } = await request("/toolkits", [["limit", "1"]]);
        return { authenticated: true, httpStatus: status };
      } catch (error) {
        if (
          error instanceof ComposioError &&
          error.code === "upstream_rejected" &&
          (error.httpStatus === 401 || error.httpStatus === 403)
        ) {
          return { authenticated: false, httpStatus: error.httpStatus };
        }
        throw error;
      }
    },

    async listToolkits(listOptions = {}) {
      const limit = validateLimit(listOptions.limit, 20);
      const search = validateOpaque(listOptions.search, 100);
      const cursor = validateOpaque(listOptions.cursor, 2_048);
      const parameters: Array<[string, string]> = [["limit", String(limit)]];
      if (search) parameters.push(["search", search]);
      if (cursor) parameters.push(["cursor", cursor]);
      const { payload } = await request("/toolkits", parameters);
      if (!isRecord(payload) || !Array.isArray(payload.items)) {
        throw new ComposioError("invalid_response");
      }
      const nextCursor = optionalString(payload.next_cursor, 2_048);
      return {
        items: payload.items.map(projectToolkit),
        ...(nextCursor ? { nextCursor } : {}),
      };
    },

    async getToolkit(slug) {
      const safeSlug = validateSlug(slug);
      const { payload } = await request(`/toolkits/${safeSlug}`, [["version", "latest"]]);
      return projectToolkit(payload);
    },

    async listConnections(listOptions = {}) {
      const limit = validateLimit(listOptions.limit, 50);
      const toolkitSlugs = validateArray(listOptions.toolkitSlugs, validateSlug);
      const statuses = validateArray(listOptions.statuses, (status) => {
        if (!CONNECTION_STATUSES.has(status)) throw new ComposioError("invalid_input");
        return status;
      });
      const userIds = validateArray(listOptions.userIds, (userId) => {
        const safe = validateOpaque(userId, 200);
        if (!safe || !/^[A-Za-z0-9._:@-]+$/u.test(safe)) {
          throw new ComposioError("invalid_input");
        }
        return safe;
      });
      const cursor = validateOpaque(listOptions.cursor, 2_048);
      const parameters: Array<[string, string]> = [["limit", String(limit)]];
      for (const slug of toolkitSlugs) parameters.push(["toolkit_slugs", slug]);
      for (const status of statuses) parameters.push(["statuses", status]);
      for (const userId of userIds) parameters.push(["user_ids", userId]);
      if (cursor) parameters.push(["cursor", cursor]);
      const { payload } = await request("/connected_accounts", parameters);
      if (!isRecord(payload) || !Array.isArray(payload.items)) {
        throw new ComposioError("invalid_response");
      }
      const nextCursor = optionalString(payload.next_cursor, 2_048);
      return {
        items: payload.items.map(projectConnection),
        ...(nextCursor ? { nextCursor } : {}),
      };
    },
  };
}
