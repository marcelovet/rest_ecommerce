class SectionNotFoundError(Exception):
    pass


class UserAlreadyExistsError(Exception):
    pass


class UserServiceError(Exception):
    pass


class AuthServiceError(Exception):
    pass


class DatabaseError(Exception):
    pass


class SelectError(DatabaseError):
    pass


class InsertError(DatabaseError):
    pass


class UpdateError(DatabaseError):
    pass


class DeleteError(DatabaseError):
    pass
