# AppZed Security Agent

Posture findings (TLS, DNSSEC, WAF, tag policy) with a dashboard. Tables self-initialize.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/naelmohammad/appzed-security-agent)

Click **Deploy to Cloudflare**: it clones this repo to your GitHub account, provisions the bindings below on your Cloudflare account, and wires CI/CD with preview URLs on every PR.

## Bindings (auto-provisioned)

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "appzed-security-agent",
  "main": "worker.js",
  "compatibility_date": "2025-09-01",
  "ai": {
    "binding": "AI"
  },
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "appzed-security-agent-db"
    }
  ],
  "triggers": {
    "crons": [
      "30 6 * * *"
    ]
  }
}
```

## Configure

Set `CF_API_TOKEN` and `CF_ACCOUNT_ID` after deploy. Ingest scanner findings via `POST /api/findings`.

```bash
wrangler secret put CF_API_TOKEN
```

Set `CF_ACCOUNT_ID` in `wrangler.jsonc` vars or as a secret.

## Try it

```bash
curl -X POST https://<your-worker>.workers.dev/api/collect
```

GET /health for a liveness check. Managed by AppZed (https://dev.appzed.com/solutions/security-agent).
