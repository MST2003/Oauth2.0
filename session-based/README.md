OAuth 2.0

---

# 🧠 OAuth 2.0 + PKCE in a Backend-for-Frontend (BFF) Architecture

## 📋 Overview

The **Backend-for-Frontend (BFF)** pattern lets a web app authenticate users securely using **OAuth 2.0 Authorization Code Flow with PKCE**, while keeping all sensitive tokens off the browser.

The **frontend** never sees or stores access/refresh tokens. Instead, the **backend** handles all OAuth 2.0 communication, stores tokens securely, and exposes only a short-lived **HttpOnly session cookie** to the browser.

---

## 🏗️ Architecture Components

| Component                          | Responsibility                                                                                            |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Frontend (Browser / React App)** | Displays UI, triggers login, and calls backend APIs with session cookie. Never stores tokens.             |
| **Backend (BFF)**                  | Handles PKCE generation, authorization code exchange, token refresh, token introspection, and revocation. |
| **Authorization Server (AS)**      | Authenticates users, issues tokens, and exposes `/token`, `/introspect`, and `/revoke` endpoints.         |

---

## 🔐 Why PKCE?

**PKCE** (Proof Key for Code Exchange) prevents attackers from using stolen authorization codes.
It uses:

* A **code_verifier**: random secret known only to backend.
* A **code_challenge**: SHA-256 hash of the verifier sent to the Authorization Server.

During token exchange, the backend must present the correct verifier — proving it was the original initiator of the flow.

---

## ⚙️ Full OAuth 2.0 + PKCE Flow (Backend-For-Frontend)

### Step 1 – User Initiates Login

The frontend redirects to:

```
GET /auth/login
```

Backend generates a PKCE verifier, challenge, and state, stores them server-side, and responds with a 302 redirect to the Authorization Server.

### Step 2 – Backend Redirects to Authorization Server

Backend responds:

```
HTTP/1.1 302 Found
Location: https://auth.thirdserver.com/authorize?
  response_type=code&
  client_id=backend-client-id&
  redirect_uri=https%3A%2F%2Fapp.example.com%2Fauth%2Fcallback&
  scope=openid%20profile%20email%20offline_access&
  state=abc123xyz&
  code_challenge=AbCdEf123...&
  code_challenge_method=S256
Set-Cookie: bff_session=xyz789; HttpOnly; Secure; SameSite=Lax
```

The browser follows the redirect and shows the Authorization Server’s login screen.

### Step 3 – User Authenticates

The Authorization Server authenticates the user, then redirects back to your backend with an authorization code:

```
https://app.example.com/auth/callback?code=auth_code_123&state=abc123xyz
```

### Step 4 – Backend Exchanges Code for Tokens

Backend verifies `state`, then exchanges the authorization code for tokens via a **server-to-server** request:

```
POST https://auth.thirdserver.com/token
grant_type=authorization_code&
code=auth_code_123&
redirect_uri=https://app.example.com/auth/callback&
client_id=backend-client-id&
code_verifier=original_verifier
```

**Response:**

```json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "def502...",
  "id_token": "eyJhbGciOi...",
  "expires_in": 3600
}
```

Backend stores tokens securely (e.g., Redis, encrypted DB), then sets a secure session cookie.

---

## 🌐 Browser Network Trace Summary

| # | Step             | Initiator                      | Description                                       |
| - | ---------------- | ------------------------------ | ------------------------------------------------- |
| 1 | `/auth/login`    | Browser → Backend              | Backend sets cookie, redirects to AS `/authorize` |
| 2 | `/authorize`     | Browser → Authorization Server | User authenticates                                |
| 3 | `/auth/callback` | Browser → Backend              | Authorization code returned                       |
| 4 | `/token`         | Backend → Authorization Server | Token exchange (server-to-server)                 |
| 5 | `/api/profile`   | Browser → Backend              | Uses stored access token                          |
| 6 | `/auth/logout`   | Browser → Backend              | Clears session and revokes tokens                 |

---

## 🧩 Redirect URI

### What It Is

The **redirect_uri** is the endpoint on your backend that receives the authorization code after a successful login.
The Authorization Server will redirect the user’s browser to this URI with `code` and `state` parameters.

### Example

```
https://app.example.com/auth/callback
```

### Requirements

* Must exactly match one of the registered redirect URIs in the Authorization Server.
* Must use HTTPS in production.
* Should point to a **backend endpoint**, not a frontend route.
* Must validate `state` to prevent CSRF.

For local development:

```
http://localhost:8000/auth/callback
```

---

## 🧱 Token Lifecycle

| Token              | Purpose                  | Where stored              | Lifetime                           |
| ------------------ | ------------------------ | ------------------------- | ---------------------------------- |
| **Access Token**   | Authorize API calls      | Backend (in memory or DB) | Short (e.g., 5–15 minutes)         |
| **Refresh Token**  | Obtain new access tokens | Backend (encrypted)       | Long (e.g., 1–30 days)             |
| **ID Token**       | Identify user            | Backend session           | Short (e.g., same as access token) |
| **Session Cookie** | Identify user session    | Browser (HttpOnly)        | Matches refresh token lifetime     |

The frontend only stores the **session cookie** — all tokens stay on the backend.

---

## 🧰 Token Introspection

### What is Introspection

**Token Introspection** is a standard OAuth 2.0 mechanism (RFC 7662) that lets your backend verify whether an **access token** (or refresh token) is still valid.

Instead of locally validating a JWT or trusting a cached token, the backend can ask the Authorization Server:

> “Is this token still active? Who does it belong to? What scopes does it have?”

### Endpoint

```
POST https://auth.thirdserver.com/introspect
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

token=<access_token>
```

### Example Response

```json
{
  "active": true,
  "scope": "openid profile email api.read",
  "client_id": "backend-client-id",
  "username": "alice@example.com",
  "token_type": "access_token",
  "exp": 1730906400,
  "sub": "user123"
}
```

### Use Cases

* Checking if an access token is revoked or expired.
* Enforcing logout or single-session policies.
* Validating opaque (non-JWT) tokens.

### Best Practice

* For JWT tokens, you can validate locally (signature, expiry).
* For opaque tokens, use introspection.
* Cache introspection results briefly (e.g., 30–60 seconds) to reduce load.

---

## 🔄 Token Revocation

### What is Revocation

**Token Revocation** (RFC 7009) allows the backend or the user to **invalidate a token** before its natural expiration time.
Once revoked, the token cannot be used to access protected resources or obtain new tokens.

### Endpoint

```
POST https://auth.thirdserver.com/revoke
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

token=<refresh_token_or_access_token>
token_type_hint=refresh_token
```

### When to Revoke

* When the user **logs out** (`/auth/logout`).
* When a **refresh token rotation** detects reuse.
* When an administrator **forces a sign-out**.
* When you suspect a **token compromise**.

### Example Flow: Logout

1. User clicks “Logout”.
2. Frontend → Backend:

   ```
   POST /auth/logout
   ```
3. Backend:

   * Looks up refresh token from session.
   * Calls `/revoke` on Authorization Server.
   * Deletes session from storage.
   * Clears `bff_session` cookie.

### Example Revocation Request

```
POST /revoke
token=def502... (refresh_token)
token_type_hint=refresh_token
Authorization: Basic base64(client_id:client_secret)
```

**Response:**

```
HTTP/1.1 200 OK
```

The Authorization Server marks the token (and its descendants) as invalid.

---

## 🧠 PKCE Recap with Example

| Step | Parameter            | Description                                         |
| ---- | -------------------- | --------------------------------------------------- |
| 1    | `code_verifier`      | Random 43–128 character string generated by backend |
| 2    | `code_challenge`     | Base64URL(SHA256(verifier))                         |
| 3    | `/authorize` request | Includes `code_challenge` and `S256`                |
| 4    | `/token` exchange    | Includes `code_verifier`                            |
| 5    | Authorization Server | Verifies hash matches → issues tokens               |

Example:

```text
code_verifier = "abcxyz123secureverifier"
code_challenge = Base64UrlEncode(SHA256("abcxyz123secureverifier"))
```

---

## 🧩 Example Backend (Flask)

```python
@app.route('/auth/login')
def auth_login():
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    state = secrets.token_urlsafe(16)
    session_id = secrets.token_urlsafe(32)
    store_session(session_id, {'code_verifier': verifier, 'state': state})
    auth_url = (
        f"{AS_AUTHORIZE}?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}&scope=openid%20profile"
        f"&state={state}&code_challenge={challenge}&code_challenge_method=S256"
    )
    resp = redirect(auth_url)
    resp.set_cookie('bff_session', session_id, httponly=True, secure=True, samesite='Lax')
    return resp
```

---

## 🧾 Example Configuration for Authorization Server

| Field                          | Example Value                           |
| ------------------------------ | --------------------------------------- |
| **Client Type**                | Confidential                            |
| **Client ID**                  | `backend-client-id`                     |
| **Redirect URIs**              | `https://app.example.com/auth/callback` |
| **Allowed Scopes**             | `openid profile email offline_access`   |
| **Grant Types**                | `authorization_code`, `refresh_token`   |
| **PKCE Enforcement**           | Required                                |
| **Token Endpoint Auth**        | `client_secret_basic` or PKCE-only      |
| **Access Token Lifetime**      | 15 minutes                              |
| **Refresh Token Lifetime**     | 30 days                                 |
| **Introspection & Revocation** | Enabled                                 |

---

## ✅ Security Checklist

| Category             | Recommendation                            |
| -------------------- | ----------------------------------------- |
| **HTTPS**            | Always use HTTPS in production.           |
| **Cookies**          | HttpOnly, Secure, SameSite=Lax or Strict. |
| **PKCE**             | Always use `S256`.                        |
| **State Validation** | Must match stored `state`.                |
| **Access Tokens**    | Short-lived (5–15 min).                   |
| **Refresh Tokens**   | Long-lived with rotation.                 |
| **Storage**          | Encrypt tokens at rest.                   |
| **Revocation**       | Revoke tokens on logout.                  |
| **Introspection**    | Use to validate opaque tokens.            |
| **Logging**          | Never log tokens.                         |

---

## 🧾 Example Redirect URIs

| Environment | Redirect URI                                |
| ----------- | ------------------------------------------- |
| Local Dev   | `http://localhost:8000/auth/callback`       |
| Staging     | `https://staging.example.com/auth/callback` |
| Production  | `https://app.example.com/auth/callback`     |

---

## 🧩 Sequence Flow Diagram (Textual)

```text
User → Browser → Backend (/auth/login)
Backend → Browser (302 to AS /authorize)
Browser → Authorization Server (/authorize)
User logs in
AS → Browser (302 to /auth/callback?code=...)
Browser → Backend (/auth/callback)
Backend → Authorization Server (/token)
AS → Backend (access_token + refresh_token)
Backend → Browser (Set-Cookie session)
Browser → Backend (/api/profile)
Backend (uses tokens)
Browser → Backend (/auth/logout)
Backend → Authorization Server (/revoke)
```

---

## 🧭 Summary of Key Endpoints

| Endpoint         | Description                         | Who Calls It                   | Sensitive Data? |
| ---------------- | ----------------------------------- | ------------------------------ | --------------- |
| `/auth/login`    | Starts login flow, generates PKCE   | Browser → Backend              | No              |
| `/authorize`     | Authorization request               | Browser → Authorization Server | No              |
| `/auth/callback` | Receives code, exchanges for tokens | Browser → Backend              | Yes (code)      |
| `/token`         | Token exchange                      | Backend → Authorization Server | Yes             |
| `/introspect`    | Token validation                    | Backend → Authorization Server | Yes             |
| `/revoke`        | Token invalidation                  | Backend → Authorization Server | Yes             |
| `/auth/logout`   | Logout endpoint                     | Browser → Backend              | No              |

---

Would you like me to now **export this as a Markdown (`.md`) or PDF** with clear section headers and formatting (for internal documentation or onboarding)?
