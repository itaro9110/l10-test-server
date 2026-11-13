// L10 — GPT Actions OAuth callback-confusion test server (skeleton, own code)
// Phase 2, Step 2 prep — OpenAI Security (Bugcrowd). NOT a finding; run only with
// the researcher's own accounts + own GPTs. No OpenAI credentials are used here.
// What it does:
//   1. Acts as a minimal OAuth 2.0 provider (authorize + token endpoints) that logs
//      EVERYTHING: code, state, redirect_uri, client_id, and which GPT callback
//      the code later arrives at.
//   2. Acts as a minimal test API (OpenAPI) the GPT Action calls, logging the
//      Authorization header / token it receives per call, so a token issued for
//      GPT-A showing up in a GPT-B call is visible in the log.
//   3. Serves an OpenAPI schema for the GPT Action editor.
//
// RUN:
//   node l10-test-server.js            # HTTP on :8080 (local dev only)
//   # For the real test it MUST be public HTTPS: put it behind a tunnel with a
//   # public hostname (e.g. Cloudflare Tunnel / ngrok) and use that hostname
//   # in the GPT Action config. TLS termination is done by the tunnel.
//   # NEVER expose this on a shared host; it logs authorization codes by design
//   # (own test codes only — rotate/revoke the test OAuth client afterwards).
//
// CONFIG (env):
//   GPT_A_ID   e.g. g-AAAAAAAAAAAAAAAAAAAAAAAA   (builder GPT)
//   GPT_B_ID   e.g. g-BBBBBBBBBBBBBBBBBBBBBBBB   (second GPT, same owner)
//   PUBLIC_BASE e.g. https://l10test.example.com  (public HTTPS base, no trailing /)
//   OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET — values you invent for YOUR provider
//     (the GPT Action editor is configured with these; they are not OpenAI creds)
//
// TESTS (run in ChatGPT UI, accounts: builder = owner of GPT-A + GPT-B,
//        user = second free account that is a USER of both GPTs):
//   T1 cross-GPT code replay: complete OAuth for GPT-A (user signs in, code lands
//      at https://chatgpt.com/aip/<GPT_A_ID>/oauth/callback). Copy the `code`
//      and `state` from YOUR provider log, then manually GET
//      https://chatgpt.com/aip/<GPT_B_ID>/oauth/callback?code=<CODE>&state=<STATE>
//      in a browser session where GPT-B's OAuth flow was started (so a state
//      cookie/session may exist). If GPT-B accepts the code and exchanges it at
//      YOUR token endpoint (check token-endpoint log for a GPT-B exchange), that
//      is cross-GPT callback confusion. Expected-secure: GPT-B rejects it
//      (state mismatch / unknown code / no token exchange logged).
//   T2 state confusion: start GPT-A flow, capture its `state`; start GPT-B flow;
//      deliver GPT-A's state to GPT-B's callback with GPT-B's code and vice versa.
//   T3 wildcard/empty callback: register the provider redirect URI as
//      https://chatgpt.com/aip/*/oauth/callback (if your provider allows it —
//      most do NOT; record whether the GPT editor even accepts a wildcard) and
//      as https://chatgpt.com/aip//oauth/callback (empty GPT id, cf. Salesforce
//      guide placeholder). Record acceptance/rejection.
//   T4 token reuse across GPTs: after the user completes OAuth in GPT-A, invoke
//      the SAME action in GPT-B (same provider, same client). Log the Bearer
//      token GPT-B sends to the test API. If it equals GPT-A's token (compare
//      in the log — tokens are per-user-per-GPT in the secure case), that is
//      cross-GPT token confusion.
//   T5 domain allowlist: workspace Settings -> set allowed Action domains to
//      ZERO / only an unrelated domain; trigger an Action call to PUBLIC_BASE.
//      If the call still reaches the test API (log shows the request), the
//      allowlist is bypassed. Record the exact workspace setting used.
//   T6 stale/revoked token: revoke the token at YOUR provider (delete it from
//      the in-memory store via POST /__test/revoke), then invoke the action
//      again. If ChatGPT still calls the API with the old token (401 logged),
//      note whether it re-prompts for sign-in or keeps using the dead token.
//
// EVIDENCE to capture per test: provider log lines (timestamped), GPT UI
// screenshots of the sign-in prompt, the token-endpoint log showing which
// redirect_uri/code was exchanged, and the test-API log showing which token
// arrived from which GPT. A finding needs the SERVER-SIDE log, not just UI.

'use strict';
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 8080;
const PUBLIC_BASE = process.env.PUBLIC_BASE || `http://127.0.0.1:${PORT}`;
const GPT_A_ID = process.env.GPT_A_ID || 'g-AAAAAAAAAAAAAAAAAAAAAAAA';
const GPT_B_ID = process.env.GPT_B_ID || 'g-BBBBBBBBBBBBBBBBBBBBBBBB';
const CLIENT_ID = process.env.OAUTH_CLIENT_ID || 'l10-test-client';
const CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || 'l10-test-secret-change-me';

const codes = new Map();   // code -> {client_id, redirect_uri, state, user, createdAt, exchanged}
const tokens = new Map();  // token -> {code, redirect_uri, state, user, createdAt, revoked}
const apiCalls = [];       // {ts, gptHint, auth, path, body}

function log(...a) {
  const line = `[${new Date().toISOString()}] ${a.join(' ')}`;
  console.log(line);
}
function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj, null, 2));
}
function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => resolve(b));
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, PUBLIC_BASE);
  const body = await readBody(req);

  // ---- OAuth authorize endpoint (user "signs in" here) ----
  if (u.pathname === '/oauth/authorize' && req.method === 'GET') {
    const client_id = u.searchParams.get('client_id');
    const redirect_uri = u.searchParams.get('redirect_uri');
    const state = u.searchParams.get('state');
    const scope = u.searchParams.get('scope');
    log('AUTHORIZE client_id=', client_id, 'redirect_uri=', redirect_uri,
        'state=', state, 'scope=', scope);
    if (client_id !== CLIENT_ID) return json(res, 400, { error: 'unknown_client' });
    if (!redirect_uri) return json(res, 400, { error: 'invalid_request', error_description: 'missing redirect_uri' });
    // Test-user identity: the "user" is whoever loads this page; use a fixed
    // test identity and let the operator pick A/B via ?test_user= param.
    const user = u.searchParams.get('test_user') || 'test-user-1';
    const code = 'code-' + crypto.randomBytes(12).toString('hex');
    codes.set(code, { client_id, redirect_uri, state, user, createdAt: Date.now(), exchanged: false });
    log('ISSUED code=', code, 'for redirect_uri=', redirect_uri, 'state=', state, 'user=', user);
    // Auto-redirect back to ChatGPT callback (this is the provider's job).
    const back = new URL(redirect_uri);
    back.searchParams.set('code', code);
    if (state) back.searchParams.set('state', state);
    res.writeHead(302, { Location: back.toString() });
    return res.end();
  }

  // ---- OAuth token endpoint (ChatGPT exchanges code -> token) ----
  if (u.pathname === '/oauth/token' && req.method === 'POST') {
    const p = new URLSearchParams(body);
    const grant = p.get('grant_type');
    const code = p.get('code');
    const redirect_uri = p.get('redirect_uri');
    const client_id = p.get('client_id');
    log('TOKEN grant=', grant, 'code=', code, 'redirect_uri=', redirect_uri, 'client_id=', client_id);
    const rec = codes.get(code);
    if (!rec) { log('TOKEN REJECTED unknown code'); return json(res, 400, { error: 'invalid_grant' }); }
    if (rec.redirect_uri !== redirect_uri) {
      log('TOKEN REJECTED redirect_uri mismatch: issued for', rec.redirect_uri, 'presented', redirect_uri);
      return json(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    }
    if (rec.exchanged) log('TOKEN NOTE code reused (replay):', code);
    rec.exchanged = true;
    const token = 'tok-' + crypto.randomBytes(16).toString('hex');
    tokens.set(token, { code, redirect_uri, state: rec.state, user: rec.user, createdAt: Date.now(), revoked: false });
    log('TOKEN ISSUED token=', token, 'for redirect_uri=', redirect_uri, 'state=', rec.state, 'user=', rec.user);
    return json(res, 200, { access_token: token, token_type: 'Bearer', expires_in: 3600, scope: 'read' });
  }

  // ---- Test API (called by the GPT Action) ----
  if (u.pathname === '/api/echo' && (req.method === 'GET' || req.method === 'POST')) {
    const auth = req.headers.authorization || '(none)';
    const entry = { ts: new Date().toISOString(), auth, path: u.pathname, body: body.slice(0, 500) };
    apiCalls.push(entry);
    log('API CALL auth=', auth, 'body=', entry.body);
    const tok = tokens.get((auth || '').replace(/^Bearer\s+/i, ''));
    return json(res, 200, {
      ok: true,
      received_auth: auth,
      token_known_to_provider: !!tok,
      token_redirect_uri: tok ? tok.redirect_uri : null,
      token_user: tok ? tok.user : null,
      token_revoked: tok ? tok.revoked : null,
      echo: body || null,
    });
  }

  // ---- OpenAPI schema for the GPT Action editor ----
  if (u.pathname === '/openapi.json') {
    return json(res, 200, {
      openapi: '3.1.0',
      info: { title: 'L10 test API', version: '1.0.0' },
      servers: [{ url: PUBLIC_BASE }],
      paths: {
        '/api/echo': {
          post: {
            operationId: 'echo',
            summary: 'Echo back the caller token (test only)',
            requestBody: { content: { 'application/json': { schema: { type: 'object' } } } },
            responses: { 200: { description: 'ok', content: { 'application/json': { schema: { type: 'object' } } } } },
            security: [{ OAuth: ['read'] }],
          },
        },
      },
      components: {
        securitySchemes: {
          OAuth: {
            type: 'oauth2',
            flows: {
              authorizationCode: {
                authorizationUrl: `${PUBLIC_BASE}/oauth/authorize`,
                tokenUrl: `${PUBLIC_BASE}/oauth/token`,
                scopes: { read: 'read test data' },
              },
            },
          },
        },
      },
    });
  }

  // ---- Test controls (phase 4 hardening: the server binds 0.0.0.0 and
  // /__test/log dumps live codes/tokens, so these routes are GATED behind a
  // one-time admin token. Start the server with a random
  // L10_ADMIN_TOKEN=<random>; call them ONLY from the VM shell against the
  // loopback URL, e.g.:
  //   curl -X POST "http://127.0.0.1:8080/__test/revoke?admin=$L10_ADMIN_TOKEN" -d "token=tok-..."
  //   curl "http://127.0.0.1:8080/__test/log?admin=$L10_ADMIN_TOKEN"
  // If L10_ADMIN_TOKEN is unset, /__test/* always 404 — never start the
  // tunnelled server without it, or T6 (revoke) cannot run. The token is
  // never the public tunnel URL's concern: tunnel traffic cannot guess it.
  const ADMIN = process.env.L10_ADMIN_TOKEN || '';
  const adminOk = ADMIN && (u.searchParams.get('admin') === ADMIN || req.headers['x-l10-admin'] === ADMIN);
  if (u.pathname === '/__test/revoke' && req.method === 'POST') {
    if (!adminOk) { res.writeHead(404); return res.end('not found'); }
    const p = new URLSearchParams(body);
    const t = tokens.get(p.get('token') || '');
    if (t) { t.revoked = true; log('REVOKED token', p.get('token')); }
    return json(res, 200, { revoked: !!t });
  }
  if (u.pathname === '/__test/log') {
    if (!adminOk) { res.writeHead(404); return res.end('not found'); }
    return json(res, 200, { codes: [...codes.entries()], tokens: [...tokens.entries()], apiCalls });
  }

  res.writeHead(404); res.end('not found');
});

server.listen(PORT, () => {
  log(`L10 test server on :${PORT}  PUBLIC_BASE=${PUBLIC_BASE}`);
  log(`GPT-A callback: https://chatgpt.com/aip/${GPT_A_ID}/oauth/callback`);
  log(`GPT-B callback: https://chatgpt.com/aip/${GPT_B_ID}/oauth/callback`);
  log(`Authorize: ${PUBLIC_BASE}/oauth/authorize  Token: ${PUBLIC_BASE}/oauth/token`);
  log(`OpenAPI:   ${PUBLIC_BASE}/openapi.json`);
});
