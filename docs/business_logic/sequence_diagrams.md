# E-Commerce API Sequence Diagrams

## User Registration and Verification

### Registration

```mermaid
sequenceDiagram
    participant C as Client
    participant AE as AuthEndpoint
    participant AS as AuthService
    participant US as UserService
    participant ES as EmailService
    participant JM as JWTMiddleware
    participant DB as Database

    %% User Registration
    C->>AE: POST /auth/register<br>(RegisterForm)
    AE->>AS: register_user(RegisterForm)
    AS->>US: get_user_by_email(RegisterForm.email)
    US->>DB: SELECT * FROM users WHERE email = ?
    alt User does not exists
        DB-->>US: null (no existing user)
        US-->>AS: None
        AS->>AS: hash_password(password)
        AS->>DB: BEGIN TRANSACTION
        AS->>DB: INSERT INTO users (is_verified = false)
        DB-->>AS: user_id
        AS->>DB: INSERT INTO user_profiles
        DB-->>AS: profile_id
        AS->>AS: create_verification_token(user_id)
        AS->>DB: INSERT INTO verification_tokens (user_id, token, expires_at)
        DB-->>AS: token_id
        AS->>DB: COMMIT TRANSACTION
        AS->>ES: send_verification_email(email, verification_token)
        ES-->>AS: email_sent
        AS->>AS: create_limited_token(user_id)
        AS-->>AE: {"success": true,<br>"token": limited_token,<br>"user": UserOut,<br>"message": "Verification email sent"}
        AE-->>C: 201 Created<br>(limitedToken, user,<br>verification pending message)
    else User exists
        DB-->>US: User (existing user)
        US-->>AS: User
        AS-->>AE: {"success": false,<br>"message": "User already exists"}
        AE-->>C: 409 Conflict<br>(user already exists)
    end
```

### Verification

```mermaid
sequenceDiagram
    participant C as Client
    participant AE as AuthEndpoint
    participant AS as AuthService
    participant US as UserService
    participant ES as EmailService
    participant JM as JWTMiddleware
    participant DB as Database

    %% Email Verification
    C->>AE: POST /auth/verify<br>(EmailVerificationForm)
    AE->>AS: verify_email(EmailVerificationForm.token)
    AS->>DB: SELECT * FROM verification_tokens WHERE token = ? AND expires_at > NOW()
    alt Token is valid
        DB-->>AS: verification_token
        AS->>DB: BEGIN TRANSACTION
        AS->>DB: UPDATE users SET is_verified = true WHERE id = ?
        AS->>DB: DELETE FROM verification_tokens WHERE id = ?
        AS->>DB: COMMIT TRANSACTION
        AS->>AS: generate_token(user_id)
        AS-->>AE: {"token":token,<br>"success": true}
        AE-->>C: 200 OK<br>(token, success message)
    else Token expired or invalid
        DB-->>AS: null (no token found)
        AS-->>AE: {"success": false}
        AE-->>C: 400 Bad Request<br>(error message)
    end
```

### Verification Resend

```mermaid
sequenceDiagram
    participant C as Client
    participant AE as AuthEndpoint
    participant AS as AuthService
    participant US as UserService
    participant ES as EmailService
    participant JM as JWTMiddleware
    participant DB as Database

    %% Resend Verification Email
    C->>AE: POST /auth/resend-verification<br>(email)
    AE->>AS: resend_verification(email)
    AS->>US: get_user_by_email(email)
    US->>DB: SELECT * FROM users WHERE email = ?
    alt User exists and not verified
        DB-->>US: User
        US-->>AS: User
        AS->>AS: User.is_verified -> False
        AS->>AS: create_verification_token(user_id)
        AS->>DB: DELETE FROM verification_tokens WHERE user_id = ?
        AS->>DB: INSERT INTO verification_tokens (user_id, token, expires_at)
        DB-->>AS: token_id
        AS->>ES: send_verification_email(email, verification_token)
        ES-->>AS: email_sent
        AS-->>AE: {"success": true}
        AE-->>C: 200 OK<br>(success message)
    else User not found
        DB-->>US: null
        US-->>AS: None
        AS-->>AE: {"success": false}
        AE-->>C: 400 Bad Request<br>(error message)
    else User already verified
        DB-->>US: User
        US-->>AS: User
        AS->>AS: User.is_verified -> True
        AS-->>AE: {"success": false}
        AE-->>C: 400 Bad Request<br>(error message)
    end
```

## User Authentication

### Login

```mermaid
sequenceDiagram
    participant C as Client
    participant AE as AuthEndpoint
    participant AS as AuthService
    participant US as UserService
    participant ES as EmailService
    participant JM as JWTMiddleware
    participant DB as Database

    %% Login Flow (with verification check)
    C->>AE: POST /auth/login<br>(UserIn)
    AE->>AS: login(UserIn)
    AS->>US: get_user_by_email(UserIn.email)
    US->>DB: SELECT * FROM users WHERE email = ?
    alt User not found
        DB-->>US: null
        US-->>AS: None
        AS-->>AE: {"success": False,<br>"verified": False,<br>"token":None,<br>"user":None}
        AE-->>C: 401 Unauthorized<br>(user not found)
    else User found
        DB-->>US: User
        US-->>AS: User
        alt User not verified
            AS->>AS: User.is_verified -> False
            AS-->>AE: {"success": False,<br>"verified": False,<br>"token":None,<br>"user":UserOut}
            AE-->>C: 403 Forbidden<br>(verification required)
        else User verified
            AS->>AS: User.is_verified -> True
            alt Password incorrect
                AS->>AS: verify_password(<br>UserIn.password, User.hashed_password<br>) -> False
                AS-->>AE: {"success": False,<br>"verified": True,<br>"token":None,<br>"user":UserOut}
                AE-->>C: 401 Unauthorized<br>(credentials incorrect)
            else Password correct
                AS->>AS: verify_password(<br>UserIn.password, User.hashed_password<br>) -> True
                AS->>AS: generate_token(User.id)
                AS-->>AE: {"success": True,<br>"verified": True,<br>"token":token,<br>"user":UserOut}
                AE-->>C: 200 OK<br>(token, user)
            end
        end
    end
```

### Authenticated Requests

```mermaid
sequenceDiagram
    participant C as Client
    participant AE as AuthEndpoint
    participant AS as AuthService
    participant US as UserService
    participant ES as EmailService
    participant JM as JWTMiddleware
    participant DB as Database

    %% Authenticated Request Flow (with verification check)
    C->>AE: GET /auth/me<br>(with Authorization header)
    AE->>JM: verify_token(token)
    JM->>JM: decode_token(token)
    JM-->>AE: {user_id}
    AE->>AS: get_user_authorized_by_id(user_id)
    AS->>US: get_user_by_id(user_id)
    US->>DB: SELECT * FROM users WHERE id = ?
    alt User not found
        DB-->>US: null
        US-->>AS: None
        AS-->>AE: {"success": False,<br>"user":None,<br>"message": "User not found"}
        AE-->>C: 401 Unauthorized<br>(credentials incorrect)
    else User found
        DB-->>US: User
        US-->>AS: UserOut
        alt User not verified
            AS->>AS: UserOut.is_authorized() -> (False, True|False)
            AS-->>AE: {"success": False,<br>"user": UserOut,<br>"message": "User is not verified"}
            AE-->>C: 403 Forbidden<br>(verification required)
        else User not active
            AS->>AS: UserOut.is_authorized() -> (True, False)
            AS-->>AE: {"success": False,<br>"user": UserOut,<br>"message": "User is inactive"}
            AE-->>C: 403 Forbidden<br>(user is inactive)
        else User verified and active
            AS->>AS: UserOut.is_authorized() -> (True, True)
            AS-->>AE: {"success": True,<br>"user":UserOut,<br>"message": "Success"}
            AE-->>C: 200 OK<br>(UserOut)
        end
    end
```

## Reset Password

```mermaid
sequenceDiagram
    participant C as Client
    participant AE as AuthEndpoint
    participant AS as AuthService
    participant US as UserService
    participant ES as EmailService
    participant JM as JWTMiddleware
    participant DB as Database

    %% Password Reset Request
    C->>AE: POST /auth/reset-password-request<br>(email)
    AE->>AS: request_password_reset(email)
    AS->>US: get_user_by_email(email)
    US->>DB: SELECT * FROM users WHERE email = ?
    alt User not found
        DB-->>US: null
        US-->>AS: None
        AS-->>AE: {"success": False, "message": "User not found"}
        AE-->>C: 200 OK (success message)
    else User found
        DB-->>US: User
        US-->>AS: User
        AS->>AS: generate_reset_token(user_id)
        AS->>DB: INSERT INTO password_reset_tokens (user_id, token, expires_at)
        DB-->>AS: token_id
        AS->>ES: send_password_reset_email(email, resetToken)
        ES-->>AS: email_sent
        AS-->>AE: {"success": True, "message": "Reset email sent"}
        AE-->>C: 200 OK (success message)
    end

    %% Password Reset Completion
    C->>AE: POST /auth/reset-password<br>(ResetPasswordForm)
    AE->>AS: reset_password(ResetPasswordForm)
    AS->>DB: SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > NOW()
    alt Token is valid
        DB-->>AS: reset_token
        AS->>AS: hash_password(ResetPasswordForm.new_password)
        AS->>DB: BEGIN TRANSACTION
        AS->>DB: UPDATE users SET hashed_password = ? WHERE id = ?
        AS->>DB: DELETE FROM password_reset_tokens WHERE id = ?
        AS->>DB: COMMIT TRANSACTION
        AS-->>AE: {"success": True, message: "Password updated"}
        AE-->>C: 200 OK (success message)
    else Token expired or invalid
        DB-->>AS: null
        AS-->>AE: {"success": False, message: "Invalid or expired token"}
        AE-->>C: 400 Bad Request (error message)
    end
```
