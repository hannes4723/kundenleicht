export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`);
}

export function hardenedHtmlHeaders(): Headers {
  return new Headers({
    "cache-control": "no-store",
    "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "content-type": "text/html; charset=utf-8",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
  });
}

export function publicJsonError(code: string, status: number, diagnostic?: unknown): Response {
  void diagnostic;
  return Response.json(
    { error: code },
    {
      status,
      headers: {
        "cache-control": "no-store",
        "content-type": "application/json; charset=utf-8",
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff",
      },
    },
  );
}

export class BodyTooLargeError extends Error {
  constructor() {
    super("body_too_large");
    this.name = "BodyTooLargeError";
  }
}

export async function readBodyWithLimit(
  request: Request,
  maximumBytes: number,
): Promise<ArrayBuffer> {
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (Number.isFinite(length) && length > maximumBytes) throw new BodyTooLargeError();
  }
  if (!request.body) return new ArrayBuffer(0);

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel().catch(() => undefined);
      throw new BodyTooLargeError();
    }
    chunks.push(value);
  }

  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result.buffer;
}

export function safeSecurityEvent(
  event: string,
  fields: Record<string, unknown>,
): Record<string, string | number> {
  const result: Record<string, string | number> = {
    event: /^[a-z0-9_:-]{1,64}$/.test(event) ? event : "invalid_event",
  };
  const requestId = fields.requestId;
  if (typeof requestId === "string" && /^[A-Za-z0-9._-]{1,64}$/.test(requestId)) {
    result.requestId = requestId;
  }
  const reason = fields.reason;
  if (typeof reason === "string" && /^[a-z0-9_:-]{1,64}$/.test(reason)) {
    result.reason = reason;
  }
  const status = fields.status;
  if (typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599) {
    result.status = status;
  }
  return result;
}
