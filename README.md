# Spring Boot JWT Authentication API

This project provides JWT access-token authentication with database-backed,
HttpOnly refresh-token cookies.

## Prerequisites

- Java 21 or newer
- PostgreSQL
- PowerShell 7 recommended for the commands below
- Values configured in `.env`:

```properties
DB_URL=jdbc:postgresql://localhost:5432/spring_auth_db
DB_USERNAME=postgres
DB_PASSWORD=your_database_password
JWT_SECRET=your_base64_encoded_secret
COOKIE_SECURE=false
```

The JWT secret must be Base64 encoded and sufficiently long for HMAC signing.
You can generate one in PowerShell:

```powershell
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes)
```

## Start the application

```powershell
.\mvnw.cmd spring-boot:run
```

The API runs at `http://localhost:8080`.

## Automated project test

Run the existing Spring context test and verify that the project compiles:

```powershell
.\mvnw.cmd clean test
```

## Endpoint tests

The examples use `curl.exe` so PowerShell does not replace `curl` with
`Invoke-WebRequest`. Refresh-token cookies are stored in `cookies.txt`.

### 1. Register a user

```powershell
curl.exe -i -c cookies.txt `
  -X POST http://localhost:8080/api/auth/register `
  -H "Content-Type: application/json" `
  -d '{"email":"user@example.com","password":"password123"}'
```

Expected result:

- Status: `200 OK`
- Response body contains `accessToken`, `email`, and `roles`
- `roles` contains `ROLE_USER`
- A `refreshToken` HttpOnly cookie is saved in `cookies.txt`

Example response:

```json
{
  "accessToken": "eyJ...",
  "email": "user@example.com",
  "roles": ["ROLE_USER"]
}
```

### 2. Reject duplicate registration

Run the registration request again with the same email.

Expected result:

- Status: `409 Conflict`
- Message says that the account already exists

### 3. Validate registration input

```powershell
curl.exe -i `
  -X POST http://localhost:8080/api/auth/register `
  -H "Content-Type: application/json" `
  -d '{"email":"not-an-email","password":"short"}'
```

Expected result: `400 Bad Request` with an object named `fieldErrors`.

### 4. Login

```powershell
$loginResponse = curl.exe -s -c cookies.txt `
  -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email":"user@example.com","password":"password123"}' |
  ConvertFrom-Json

$accessToken = $loginResponse.accessToken
$loginResponse
```

Expected result:

- Status: `200 OK`
- A JWT is assigned to `$accessToken`
- A new refresh-token cookie replaces the previous refresh token

### 5. Reject incorrect login credentials

```powershell
curl.exe -i `
  -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email":"user@example.com","password":"incorrect-password"}'
```

Expected result: `401 Unauthorized` with `Invalid email or password`.

### 6. Get the authenticated user

First run the login test so `$accessToken` contains a valid token.

```powershell
curl.exe -i `
  http://localhost:8080/api/auth/me `
  -H "Authorization: Bearer $accessToken"
```

Expected result: `200 OK` with the user's ID, email, roles, and enabled state.

### 7. Reject an unauthenticated request

```powershell
curl.exe -i http://localhost:8080/api/auth/me
```

Expected result: `401 Unauthorized`.

### 8. Reject an invalid access token

```powershell
curl.exe -i `
  http://localhost:8080/api/auth/me `
  -H "Authorization: Bearer invalid-token"
```

Expected result: `401 Unauthorized`.

### 9. Refresh the access token

The login request must have already populated `cookies.txt`.

```powershell
$refreshResponse = curl.exe -s -b cookies.txt -c cookies.txt `
  -X POST http://localhost:8080/api/auth/refresh |
  ConvertFrom-Json

$accessToken = $refreshResponse.accessToken
$refreshResponse
```

Expected result:

- Status: `200 OK`
- A new access token is returned
- The old refresh token is revoked
- A rotated refresh-token cookie is saved

### 10. Reject refresh without a cookie

```powershell
curl.exe -i -X POST http://localhost:8080/api/auth/refresh
```

Expected result: `401 Unauthorized` with `Refresh token is missing`.

### 11. Reject refresh-token reuse

Save one login cookie separately, refresh it once, and then try the original
cookie again:

```powershell
curl.exe -s -c old-cookies.txt `
  -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email":"user@example.com","password":"password123"}' > $null

Copy-Item old-cookies.txt rotated-cookies.txt

curl.exe -i -b rotated-cookies.txt -c rotated-cookies.txt `
  -X POST http://localhost:8080/api/auth/refresh

curl.exe -i -b old-cookies.txt `
  -X POST http://localhost:8080/api/auth/refresh
```

The first refresh should return `200 OK`. Reusing the original token should
return `401 Unauthorized` because it has been revoked.

### 12. Deny a normal user access to the admin endpoint

```powershell
curl.exe -i `
  http://localhost:8080/api/admin/dashboard `
  -H "Authorization: Bearer $accessToken"
```

Expected result: `403 Forbidden` because a registered user has `ROLE_USER`.

### 13. Access the admin endpoint

Promote the test user in PostgreSQL:

```sql
INSERT INTO user_roles (user_id, role)
SELECT id, 'ROLE_ADMIN'
FROM app_user
WHERE email = 'user@example.com'
  AND NOT EXISTS (
    SELECT 1
    FROM user_roles ur
    WHERE ur.user_id = app_user.id
      AND ur.role = 'ROLE_ADMIN'
  );
```

Log in again to obtain a new access token, then test the endpoint:

```powershell
$adminLogin = curl.exe -s -c cookies.txt `
  -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email":"user@example.com","password":"password123"}' |
  ConvertFrom-Json

$adminToken = $adminLogin.accessToken

curl.exe -i `
  http://localhost:8080/api/admin/dashboard `
  -H "Authorization: Bearer $adminToken"
```

Expected result: `200 OK` with the admin welcome message.

### 14. Logout

```powershell
curl.exe -i -b cookies.txt -c cookies.txt `
  -X POST http://localhost:8080/api/auth/logout `
  -H "Authorization: Bearer $accessToken"
```

Expected result:

- Status: `204 No Content`
- The stored refresh token is revoked
- The browser refresh-token cookie is cleared

### 15. Verify refresh fails after logout

```powershell
curl.exe -i -b cookies.txt `
  -X POST http://localhost:8080/api/auth/refresh
```

Expected result: `401 Unauthorized` because the cookie was cleared. If an old
cookie is manually reused, it is rejected because its database record is
revoked.

## Endpoint summary

| Method | Endpoint | Authentication | Expected success |
|---|---|---|---|
| `POST` | `/api/auth/register` | Public | `200 OK` |
| `POST` | `/api/auth/login` | Public | `200 OK` |
| `POST` | `/api/auth/refresh` | Refresh cookie | `200 OK` |
| `POST` | `/api/auth/logout` | Access token | `204 No Content` |
| `GET` | `/api/auth/me` | Access token | `200 OK` |
| `GET` | `/api/admin/dashboard` | `ROLE_ADMIN` access token | `200 OK` |

