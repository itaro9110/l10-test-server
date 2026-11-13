# L10 test server (throwaway OAuth2 provider)

Test provider for the OpenAI Security bug bounty (Bugcrowd) — GPT Actions
OAuth callback research (lead L10). It implements a minimal OAuth2
authorization-code flow plus a test API, so the researcher can check
whether ChatGPT binds an OAuth code/token to the GPT that requested it
(cross-GPT replay, state confusion, token reuse, revoked-token handling).

**This is a test harness, not a real service.** It invents its own client
id/secret, issues random codes/tokens kept only in memory, and has no real
users or data. The debug endpoints (`/__test/*`) are gated behind an
`L10_ADMIN_TOKEN` env var and return 404 without it.

## Run

```
PUBLIC_BASE=https://<public-url> \
OAUTH_CLIENT_ID=l10-test-client \
OAUTH_CLIENT_SECRET=<random> \
L10_ADMIN_TOKEN=<random> \
node l10-test-server.js
```

`PORT` defaults to 8080. `GPT_A_ID` / `GPT_B_ID` are only used for the
startup log lines (the callback URLs); the OAuth endpoints enforce the
`redirect_uri` bound to each issued code.

## Endpoints

- `GET /openapi.json` — OpenAPI schema for the GPT Action editor
- `GET /oauth/authorize` — issues a code bound to the given `redirect_uri` + `state`, then 302s back
- `POST /oauth/token` — exchanges a code; enforces `redirect_uri` match; rejects unknown/replayed codes
- `GET|POST /api/echo` — returns what token arrived and what the provider knows about it
- `GET /__test/log`, `POST /__test/revoke` — gated behind `L10_ADMIN_TOKEN`
