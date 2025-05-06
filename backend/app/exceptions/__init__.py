class APIError(Exception):
    """
    Base class for all exceptions raised by the API
    """


# Config errors
class SectionNotFoundError(APIError):
    pass


# Security errors
class SecurityError(APIError):
    pass


class BlockedIPError(SecurityError):
    pass


# Auth service errors
class AuthServiceError(APIError):
    pass


class UserAlreadyExistsError(AuthServiceError):
    pass


# User service errors
class UserServiceError(APIError):
    pass


# JWT service errors
class TokenRevokedError(AuthServiceError):
    pass


# Database errors
class DatabaseError(APIError):
    pass


class SelectError(DatabaseError):
    pass


class InsertError(DatabaseError):
    pass


class UpdateError(DatabaseError):
    pass


class DeleteError(DatabaseError):
    pass
