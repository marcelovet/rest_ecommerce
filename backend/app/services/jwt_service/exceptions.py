# JWT service errors
class JWTServiceError(Exception):
    pass


class TokenRevokedError(JWTServiceError):
    pass


class TokenRepositoryError(JWTServiceError):
    pass


class MissingRequiredScopeError(JWTServiceError):
    pass
