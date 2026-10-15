declare global {
  namespace Cloudflare {
    interface Env {
      OAUTH_KV: KVNamespace;
      COMPOSIO_API_KEY: string;
      GOOGLE_CLIENT_ID: string;
      GOOGLE_CLIENT_SECRET: string;
      OAUTH_RATE_LIMITER: RateLimit;
      DCR_RATE_LIMITER: RateLimit;
    }
  }
}

export {};
