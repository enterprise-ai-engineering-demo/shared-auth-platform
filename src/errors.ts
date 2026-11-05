export class AuthError extends Error {
  constructor(
    public readonly status: 401 | 403,
    public readonly code: 'UNAUTHORIZED' | 'FORBIDDEN',
    message: string,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}
