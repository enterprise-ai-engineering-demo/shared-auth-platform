# Shared authentication platform

Lightweight TypeScript JWT generation, verification, Express middleware, and
role-based authorization. Requires Node.js 22.9+; supports Express 4.18+ and 5.
Exports CommonJS JavaScript and TypeScript declarations.

## Install across repositories

Build a versioned package locally (no registry publication required):

```bash
npm ci
npm test
npm pack
# From a consuming repository:
npm install /path/to/enterprise-ai-engineering-demo-shared-auth-platform-1.0.0.tgz
```

The package name is `@enterprise-ai-engineering-demo/shared-auth-platform`.
Express is a peer dependency; consumers supply their own Express installation.
The only runtime dependency is `jsonwebtoken`.

## Configuration

Copy `.env.example` to `.env`. Generate a secret with
`node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`.
Set the **same configuration** in the trusted issuer and backend:

| Variable | Default | Requirement |
| --- | --- | --- |
| `JWT_SECRET` | None | Required, at least 32 UTF-8 bytes |
| `JWT_ISSUER` | `customer-management-demo` | Non-empty string |
| `JWT_AUDIENCE` | `customer-management-api` | Non-empty string |

The library reads `process.env`; it does not load `.env` files itself. Start your
application with `node --env-file-if-exists=.env dist/server.js`, or use your
deployment's environment injection. Invalid configuration throws at startup.
You can also pass `{ secret, issuer?, audience? }` explicitly to token helpers and
`createAuthMiddleware`. Omitted configuration loads the environment; an explicit
configuration object must include the secret.

Never commit real secrets or tokens. Keep the signing secret on trusted servers,
not in browser/mobile clients. This library is not a login endpoint or identity
provider: validate credentials before issuing tokens, assign roles server-side,
and use HTTPS. Every service holding an HS256 secret can also mint tokens.

## Generate and verify tokens

```ts
import {
  generateToken, loadAuthConfig, verifyToken,
} from '@enterprise-ai-engineering-demo/shared-auth-platform';

const config = loadAuthConfig();
const token = generateToken({ subject: 'demo-user' }, config);
const claims = verifyToken(token, config);
console.log(claims.sub); // demo-user; never log the token itself

const adminToken = generateToken(
  { subject: 'admin-user', roles: ['admin'] },
  config,
  { expiresIn: '15m' }, // default is 1h; numeric values are seconds
);
```

CommonJS consumers use `const { generateToken } = require('...')`.
`verifyToken` returns `AuthClaims` or throws a `jsonwebtoken` verification error;
bad configuration throws a configuration error. It never uses decode-only JWT
parsing to authenticate.

## Compatibility with customer-management-api

The contract follows `src/auth.js` and `scripts/create-token.js` in
`enterprise-ai-engineering-demo/customer-management-api` at commit
`bd38112fe5726d24a0a5e507dea5a1eea7dc371a`:

- **HS256 only**; verification pins the algorithm, issuer, and audience.
- Generation uses `sub` for the supplied subject and standard `iss`, `aud`,
  `iat`, and `exp` claims. Default lifetime is one hour, matching the backend helper.
- Requests use `Authorization: Bearer <token>`; verified claims live on `req.auth`.
- Verification enforces `exp` and `nbf` when present. Like the backend, it does not
  require either claim or `sub` on incoming tokens; generation always sets
  `sub` and an expiration.

Tokens generated here work with the existing backend middleware without changing
that repository, provided all three configuration values match. Tokens generated
by its helper work here too.

The backend has no role claim or role policy. `roles?: string[]` is an optional,
additive extension for consumers opting into authorization; no role is invented
for existing tokens. Tokens without roles still authenticate but cannot pass a
role policy. If present, `roles` must contain only non-empty strings; the shared
verifier rejects malformed roles. Roles are case-sensitive and have no implicit
hierarchy or wildcard semantics.

## Express integration

```ts
import express, { type ErrorRequestHandler } from 'express';
import {
  AuthError, createAuthMiddleware, loadAuthConfig, requireRoles,
} from '@enterprise-ai-engineering-demo/shared-auth-platform';

const app = express();
const auth = createAuthMiddleware(loadAuthConfig()); // validate once at startup
app.get('/health', (_req, res) => { res.json({ status: 'ok' }); });
app.get('/profile', auth, (req, res) => { res.json({ subject: req.auth?.sub }); });
app.get('/admin', auth, requireRoles('admin', 'operator'), (_req, res) => {
  res.json({ allowed: true });
});

const authErrors: ErrorRequestHandler = (error, _req, res, next) => {
  if (!(error instanceof AuthError)) return next(error);
  res.status(error.status).json({
    error: { code: error.code, message: error.message },
  });
};
app.use(authErrors);
// Register your general application error handler after this.
```

`requireRoles(...roles)` allows **any one** listed role, rejects an empty policy
at setup, returns 401 without `req.auth`, and returns 403 for insufficient roles.
Always run authentication first; never populate `req.auth` from untrusted input.
`hasRole(claims, role)` is the equivalent predicate for non-Express callers and
must receive verified claims.

Authentication failures call `next(new AuthError(401, 'UNAUTHORIZED', ...))`.
Missing/malformed authorization headers set `WWW-Authenticate: Bearer`; rejected
tokens set `WWW-Authenticate: Bearer error="invalid_token"`. Unexpected errors
are forwarded unchanged. Middleware does not send response bodies.

### Replacing the backend middleware

The backend's existing error handler requires `instanceof ApiError`, not merely a
matching status/code. If replacing its middleware with this library, insert this
CommonJS adapter **before** its `errorHandler`:

```js
const { AuthError, createAuthMiddleware } =
  require('@enterprise-ai-engineering-demo/shared-auth-platform');
const { ApiError, errorHandler } = require('./errors');

// Use createAuthMiddleware(config.auth) on the existing protected router.
app.use((error, req, res, next) => {
  next(error instanceof AuthError
    ? new ApiError(error.status, error.code, error.message)
    : error);
});
app.use(errorHandler);
```

This preserves the backend's error envelope and avoids turning expected
authentication failures into 500 responses. No adapter is needed if the backend
keeps its existing verifier and only consumes tokens issued by this package.

## API and development

Exports: `generateToken`, `verifyToken`, `loadAuthConfig`, `validateAuthConfig`,
`createAuthMiddleware`, `hasRole`, `requireRoles`, and `AuthError`.
Shared types: `AuthConfig`, `AuthConfigInput`, `AuthClaims`, `TokenInput`, and
`TokenOptions`. Importing the package also types Express's optional `req.auth`.

```bash
npm ci
npm test       # TypeScript build and Node.js unit/Express integration tests
npm run build # dist/ JavaScript and declarations
```

Tests use isolated, test-only configuration and no running server. They cover
backend-compatible tokens, invalid configuration, temporal/signature/algorithm/
issuer/audience rejection, Bearer parsing, verified request claims, and RBAC.
