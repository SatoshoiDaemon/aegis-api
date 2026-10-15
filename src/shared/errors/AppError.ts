export class AppError extends Error {
  public readonly statusCode: number;
  public readonly errorLabel: string;
  public readonly isOperational: boolean;

  constructor(message: string, errorLabel: string = 'internal_error', statusCode: number = 400, isOperational: boolean = true) {
    super(message);
    this.name = 'AppError';
    this.errorLabel = errorLabel;
    this.statusCode = statusCode;
    this.isOperational = isOperational;

    Error.captureStackTrace(this, this.constructor);
  }
}

export const DomainErrors = {
  ServiceUnavailable: new AppError('Authentication dependency unavailable; retry later', 'service_unavailable', 503),
  InvalidCredentials: new AppError('Email or password is incorrect', 'invalid_credentials', 401),
  UserAlreadyExists: new AppError('User already exists', 'user_already_exists', 409),
  InvalidToken: new AppError('Invalid or malformed token', 'invalid_token', 401),
  TokenExpired: new AppError('Token has expired', 'token_expired', 401),
  SessionReuseDetected: new AppError('Session reuse detected. All sessions have been revoked.', 'session_reuse_detected', 401),
  SessionNotFound: new AppError('Session not found', 'session_not_found', 404),
};
