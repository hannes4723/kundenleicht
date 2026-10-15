import type { ConsentDescription } from "@cloudflare/workers-oauth-provider";
import { escapeHtml, hardenedHtmlHeaders } from "./security";

const AUTHORIZE_PATH = "/mcp/admin/authorize";

export function consentPage(details: ConsentDescription, handle: string): string {
  const clientName = escapeHtml(details.clientName);
  const clientOrigin = details.clientDomain
    ? `Veröffentlicht von <strong>${escapeHtml(details.clientDomain)}</strong>.`
    : "Diese Anwendung hat sich selbst registriert; ihr Name ist nicht verifiziert.";
  const loopbackWarning = details.redirectIsLoopback
    ? "<p><strong>Die Berechtigung wird an eine Anwendung auf diesem Gerät gesendet. Fahren Sie nur fort, wenn Sie die Anmeldung gerade selbst gestartet haben.</strong></p>"
    : "";
  const scopes = details.scope
    .map(
      (scope) =>
        `<label><input type="checkbox" name="scope" value="${escapeHtml(scope)}" checked> ${escapeHtml(scope)}</label>`,
    )
    .join("<br>");

  return `<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kundenleicht-Zugriff erlauben</title>
<style>body{font:16px system-ui,sans-serif;max-width:44rem;margin:3rem auto;padding:0 1rem;color:#17202a}main{border:1px solid #d5d8dc;border-radius:12px;padding:1.5rem}button{padding:.65rem 1rem;margin:.75rem .5rem 0 0}code{overflow-wrap:anywhere}</style></head>
<body><main><h1>Zugriff erlauben?</h1>
<p><strong>${clientName}</strong> möchte den Kundenleicht-Verwaltungszugang verwenden.</p>
<p>${clientOrigin} Die Berechtigung wird an <strong>${escapeHtml(details.redirectHost)}</strong> gesendet.</p>
${loopbackWarning}
<form method="post" action="${AUTHORIZE_PATH}">
<input type="hidden" name="handle" value="${escapeHtml(handle)}">
<fieldset><legend>Berechtigung</legend>${scopes}</fieldset>
<p><button type="submit" name="decision" value="approve">Erlauben</button><button type="submit" name="decision" value="deny">Ablehnen</button></p>
</form></main></body></html>`;
}

export function errorPage(title: string, message: string): string {
  return `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title></head><body><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></main></body></html>`;
}

export function googleTransitionPage(location: string): string {
  const url = new URL(location);
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hostname !== "accounts.google.com" ||
    url.pathname !== "/o/oauth2/v2/auth"
  ) {
    throw new TypeError("Invalid Google authorization URL");
  }
  const href = escapeHtml(url.toString());
  return `<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Weiter zur Google-Anmeldung</title>
<style>body{font:16px system-ui,sans-serif;max-width:44rem;margin:3rem auto;padding:0 1rem;color:#17202a}main{border:1px solid #d5d8dc;border-radius:12px;padding:1.5rem}a{display:inline-block;padding:.7rem 1rem;border-radius:8px;background:#1a73e8;color:#fff;text-decoration:none}</style></head>
<body><main><h1>Berechtigung bestätigt</h1><p>Öffnen Sie jetzt die sichere Google-Anmeldung.</p><p><a href="${href}" rel="noreferrer">Weiter zu Google</a></p></main></body></html>`;
}

export function htmlResponse(
  body: string,
  status: number,
  initialHeaders?: Headers,
): Response {
  const headers = initialHeaders ?? new Headers();
  for (const [name, value] of hardenedHtmlHeaders()) headers.set(name, value);
  return new Response(body, { status, headers });
}

export function redirectResponse(location: string, headers = new Headers()): Response {
  headers.set("location", location);
  headers.set("cache-control", "no-store");
  headers.set("referrer-policy", "no-referrer");
  headers.set("x-content-type-options", "nosniff");
  return new Response(null, { status: 302, headers });
}
