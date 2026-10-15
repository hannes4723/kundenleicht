import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      return entry.isDirectory() ? sourceFiles(path) : [path];
    }),
  );
  return nested.flat();
}

const bundle = await readFile("dist/index.js", "utf8");
const config = await readFile("wrangler.jsonc", "utf8");
const sources = await sourceFiles("src");
const source = (
  await Promise.all(sources.map(async (path) => `${path}\n${await readFile(path, "utf8")}`))
).join("\n");

const forbiddenBundleValues = [
  "test-composio-api-key",
  "test-google-client-secret",
  "discard-upstream-token",
  "valid-access-token",
  "SENTINEL-BEARER-TOKEN",
  "-----BEGIN PRIVATE KEY-----",
];
const failures = [];

for (const value of forbiddenBundleValues) {
  if (bundle.includes(value)) failures.push(`bundle contains forbidden fixture: ${value}`);
}
if (/console\.(?:debug|error|info|log|warn)\s*\(/u.test(source)) {
  failures.push("application source contains a console logging call");
}
if (!/"redact_query_string"\s*:\s*true/u.test(config)) {
  failures.push("Wrangler observability does not redact OAuth query strings");
}
if (/"routes"\s*:/u.test(config)) {
  failures.push("Wrangler config must not mutate production routes during code deployment");
}

if (failures.length > 0) {
  throw new Error(failures.join("\n"));
}

process.stdout.write("Bundle security scan passed.\n");
