const { test } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const {
  AuthError,
  createAuthMiddleware,
  generateToken,
  hasRole,
  loadAuthConfig,
  requireRoles,
  validateAuthConfig,
  verifyToken,
} = require('..');

const config = validateAuthConfig({
  secret: 'test-only-secret-with-at-least-32-bytes',
});

// Matches customer-management-api/scripts/create-token.js and its test helper.
function backendToken(options = {}, payload = {}, secret = config.secret) {
  return jwt.sign(payload, secret, {
    algorithm: 'HS256',
    subject: 'demo-user',
    issuer: config.issuer,
    audience: config.audience,
    expiresIn: '1h',
    ...options,
  });
}

function app(...middleware) {
  const instance = express();
  instance.get('/', ...middleware, (req, res) => res.json(req.auth));
  instance.use((error, _req, res, _next) => {
    assert.ok(error instanceof AuthError);
    res.status(error.status).json({
      error: { code: error.code, message: error.message },
    });
  });
  return instance;
}

test('configuration matches backend defaults and environment overrides', () => {
  assert.deepEqual(loadAuthConfig({ JWT_SECRET: config.secret }), config);
  assert.deepEqual(loadAuthConfig({
    JWT_SECRET: config.secret,
    JWT_ISSUER: 'custom-issuer',
    JWT_AUDIENCE: 'custom-api',
  }), { secret: config.secret, issuer: 'custom-issuer', audience: 'custom-api' });
});

test('invalid configuration fails fast; secret length is measured in bytes', () => {
  for (const secret of [undefined, '', 'short', 'a'.repeat(31)]) {
    assert.throws(() => validateAuthConfig({ secret }), /JWT_SECRET/);
  }
  assert.throws(() => loadAuthConfig({}), /JWT_SECRET/);
  assert.throws(() => createAuthMiddleware({ secret: 'short' }), /JWT_SECRET/);
  for (const field of ['issuer', 'audience']) {
    for (const value of ['', ' ', null, 123]) {
      assert.throws(() => validateAuthConfig({ ...config, [field]: value }),
        /JWT_ISSUER and JWT_AUDIENCE/);
    }
  }
  assert.equal(validateAuthConfig({ secret: '\u00e9'.repeat(16) }).secret,
    '\u00e9'.repeat(16));
});

test('generation uses the exact backend format and one-hour default', () => {
  const token = generateToken({ subject: 'demo-user' }, config);
  const decoded = jwt.decode(token, { complete: true });
  assert.equal(decoded.header.alg, 'HS256');
  assert.deepEqual(Object.keys(decoded.payload).sort(),
    ['aud', 'exp', 'iat', 'iss', 'sub']);
  assert.equal(decoded.payload.exp - decoded.payload.iat, 3600);
  // These are the backend middleware's exact verification options.
  const claims = jwt.verify(token, config.secret, {
    algorithms: ['HS256'],
    issuer: config.issuer,
    audience: config.audience,
  });
  assert.equal(claims.sub, 'demo-user');
});

test('verifies tokens produced by the existing backend helper', () => {
  assert.equal(verifyToken(backendToken(), config).sub, 'demo-user');
  // The backend checks temporal claims when present, not their presence.
  const legacy = jwt.sign({}, config.secret, {
    algorithm: 'HS256', issuer: config.issuer, audience: config.audience,
  });
  assert.equal(verifyToken(legacy, config).iss, config.issuer);
});

test('supports optional roles, custom lifetime and custom issuer/audience', () => {
  const custom = { ...config, issuer: 'issuer-2', audience: 'api-2' };
  const token = generateToken({ subject: 'user-2', roles: ['admin', 'reader'] },
    custom, { expiresIn: 120 });
  const claims = verifyToken(token, custom);
  assert.deepEqual(claims.roles, ['admin', 'reader']);
  assert.equal(claims.exp - claims.iat, 120);
  assert.throws(() => verifyToken(token, config), jwt.JsonWebTokenError);
});

test('rejects invalid token input and malformed role claims', () => {
  for (const subject of ['', ' ', undefined, 123]) {
    assert.throws(() => generateToken({ subject }, config), /subject/);
  }
  for (const roles of ['admin', [123], [''], [' '], null]) {
    assert.throws(() => generateToken({ subject: 'user', roles }, config), /roles/);
    assert.throws(() => verifyToken(backendToken({}, { roles }), config),
      jwt.JsonWebTokenError);
  }
});

const invalidTokens = {
  malformed: 'not-a-jwt',
  expired: () => backendToken({ expiresIn: -1 }),
  signature: () => backendToken({}, {}, 'another-test-only-secret-of-32-bytes'),
  issuer: () => backendToken({ issuer: 'other' }),
  audience: () => backendToken({ audience: 'other' }),
  missingIssuer: () => jwt.sign({ aud: config.audience }, config.secret),
  missingAudience: () => jwt.sign({ iss: config.issuer }, config.secret),
  algorithm: () => backendToken({ algorithm: 'HS384' }),
  unsigned: () => backendToken({ algorithm: 'none' }),
  future: () => backendToken({ notBefore: '1h' }),
  roles: () => backendToken({}, { roles: 'admin' }),
};

for (const [reason, makeToken] of Object.entries(invalidTokens)) {
  test(`verification and middleware reject ${reason} tokens`, async () => {
    const token = typeof makeToken === 'function' ? makeToken() : makeToken;
    assert.throws(() => verifyToken(token, config), jwt.JsonWebTokenError);
    const response = await request(app(createAuthMiddleware(config)))
      .get('/').set('Authorization', `Bearer ${token}`);
    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, 'UNAUTHORIZED');
    assert.equal(response.headers['www-authenticate'], 'Bearer error="invalid_token"');
  });
}

test('middleware requires a single Bearer token', async () => {
  const instance = app(createAuthMiddleware(config));
  for (const header of [undefined, '', 'Basic abc', 'Bearer', 'Bearer a b',
    'Bearer  abc']) {
    const pending = request(instance).get('/');
    if (header !== undefined) pending.set('Authorization', header);
    const response = await pending;
    assert.equal(response.status, 401);
    assert.equal(response.headers['www-authenticate'], 'Bearer');
    assert.equal(response.body.error.code, 'UNAUTHORIZED');
  }
});

test('middleware exposes verified claims and supports case-insensitive scheme', async () => {
  const response = await request(app(createAuthMiddleware(config)))
    .get('/').set('Authorization', `bEaReR ${backendToken()}`);
  assert.equal(response.status, 200);
  assert.equal(response.body.sub, 'demo-user');
  assert.equal(response.body.roles, undefined);
});

test('hasRole uses exact matches and denies absent or malformed roles', () => {
  assert.equal(hasRole({ roles: ['admin'] }, 'admin'), true);
  assert.equal(hasRole({ roles: ['admin'] }, 'Admin'), false);
  for (const claims of [undefined, {}, { roles: 'admin' }, { roles: [123] }]) {
    assert.equal(hasRole(claims, 'admin'), false);
  }
});

test('role policies reject empty or malformed configuration', () => {
  assert.throws(() => requireRoles(), /role/);
  assert.throws(() => requireRoles(''), /role/);
  assert.throws(() => requireRoles('admin', 123), /role/);
});

test('role middleware distinguishes unauthenticated, forbidden, and authorized', async () => {
  const unauthenticated = await request(app(requireRoles('admin'))).get('/');
  assert.equal(unauthenticated.status, 401);
  assert.equal(unauthenticated.body.error.code, 'UNAUTHORIZED');
  const instance = app(createAuthMiddleware(config), requireRoles('admin', 'editor'));
  for (const roles of [undefined, [], ['reader'], ['Admin'], ['editor'], ['admin']]) {
    const token = generateToken({ subject: 'user', roles }, config);
    const response = await request(instance).get('/')
      .set('Authorization', `Bearer ${token}`);
    const allowed = roles?.includes('admin') || roles?.includes('editor');
    assert.equal(response.status, allowed ? 200 : 403);
    if (!allowed) assert.equal(response.body.error.code, 'FORBIDDEN');
  }
});

test('authentication clears pre-existing claims before rejecting a request', () => {
  const req = { auth: { roles: ['admin'] }, get: () => undefined };
  const res = { set() {} };
  let failure;
  createAuthMiddleware(config)(req, res, (error) => { failure = error; });
  assert.equal(req.auth, undefined);
  assert.ok(failure instanceof AuthError);
});

test('errors from downstream middleware are not reclassified as token failures', () => {
  const req = { get: () => `Bearer ${backendToken()}` };
  const res = { set: () => assert.fail('Unexpected authentication challenge') };
  const downstream = new Error('downstream failure');
  assert.throws(() => createAuthMiddleware(config)(req, res, () => {
    throw downstream;
  }), (error) => error === downstream);
});
