import type { AuthConfig, AuthConfigInput } from './types';

export function validateAuthConfig({
  secret,
  issuer = 'customer-management-demo',
  audience = 'customer-management-api',
}: AuthConfigInput = {}): AuthConfig {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) {
    throw new Error('JWT_SECRET must be set to a secret of at least 32 bytes.');
  }
  if (typeof issuer !== 'string' || !issuer.trim() ||
      typeof audience !== 'string' || !audience.trim()) {
    throw new Error('JWT_ISSUER and JWT_AUDIENCE must be non-empty strings.');
  }
  return { secret, issuer, audience };
}

export function loadAuthConfig(env: NodeJS.ProcessEnv = process.env): AuthConfig {
  return validateAuthConfig({
    secret: env.JWT_SECRET,
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
  });
}
