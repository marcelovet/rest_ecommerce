class APIError(Exception):
    """
    Base class for all exceptions raised by the API
    """


class SectionNotFoundError(APIError):
    pass


class UserAlreadyExistsError(APIError):
    pass


class UserServiceError(APIError):
    pass


class AuthServiceError(APIError):
    pass


class TokenRevokedError(AuthServiceError):
    pass


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
