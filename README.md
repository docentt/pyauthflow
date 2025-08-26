# PyAuthFlow - OAuth 2.0 / OIDC Token Manager

**PyAuthFlow** is a lightweight, zero-dependency Python module for managing OAuth 2.0 and OpenID Connect (OIDC) tokens.

It supports device authorization, authorization code grant (with optional PKCE), token refresh, revocation, introspection, and secure local storage - all with a clean, user-friendly interface.

Designed for interactive environments like Jupyter notebooks, CLI tools, or lightweight scripts, PyAuthFlow helps developers handle OAuth flows without the need for full web frameworks.

## ✨ Features

- 🔐 **Device Authorization Grant** (a.k.a. *Device Flow*)  
  Enables headless or CLI-based authentication.  
  **[RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)**

- 🧭 **Authorization Code Grant (with optional PKCE)**  
  Supports full browser-based authorization with redirect and optional client secret.  
  **[RFC 6749 §4.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)**  
  **[RFC 7636 (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)**

- 🔄 **Token Refresh**  
  Automatically refreshes access tokens using a valid refresh token,  
  only when the remaining lifetime is below a configurable threshold (`min_ttl`, default: 60 seconds).  
  **[RFC 6749 §6](https://datatracker.ietf.org/doc/html/rfc6749#section-6)**

- 🚫 **Token Revocation**  
  Supports revoking both access and refresh tokens.  
  **[RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)**

- 🕵️‍♂️ **Token Introspection**  
  Queries token status and metadata from the authorization server.  
  **[RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)**

- 💾 **Secure Local Caching**  
  Stores and retrieves token entries in a flat JSON file at:  
  `~/.pyauthflow_token_store.json`.

- 🧹 **Selective Token Cleanup**  
  Revoke and remove individual token entries or purge the entire store,  
  with optional revocation for online and offline tokens.

## 📦 Installation

PyAuthFlow is dependency-free - just download `token_manager.py`.

### Option 1 - 📥 Download the file directly

```bash
curl -O https://raw.githubusercontent.com/docentt/pyauthflow/main/token_manager.py
```

### Option 2 - 🧬 Clone the full repository

```bash
git clone https://github.com/docentt/pyauthflow.git
```

### Option 3 - 📓 Load in Jupyter Notebook

Paste this into a notebook cell:

```python
!git clone https://github.com/docentt/pyauthflow.git
import sys
sys.path.insert(0, "pyauthflow")
```

## 🚀 Usage Example

### Device Authorization Grant

```python
from token_manager import get_access_token_with_interactive_device_flow

client_id = "your-client-id"
issuer = "https://your.issuer.com"
scope = "openid profile email"

token = get_access_token_with_interactive_device_flow(client_id, issuer, scope)

if token:
    print("✅ Access token:", token)
else:
  print("❌ Token acquisition failed.")
```
✅ This handles caching, refresh, and the full device flow transparently.

### Authorization Code Grant

```python
from token_manager import (
  get_access_token_with_interactive_authorization_code_flow,
  complete_authorization_code_exchange,
)

client_id = "your-client-id"
issuer = "https://your.issuer.com"
redirect_uri = "http://localhost:8000/callback"
scope = "openid profile offline_access"

# Step 1: Try from cache or start browser-based login
token = get_access_token_with_interactive_authorization_code_flow(client_id, issuer, redirect_uri, scope)

# Step 2: If the flow was initiated, ask the user to paste code & state
if not token:
  print("\nPaste the `code` and `state` values from the browser redirect URL:")
  code = input("🔤 Authorization Code: ").strip()
  state = input("🔐 State: ").strip()

  token = complete_authorization_code_exchange(client_id, issuer, scope, code, state)

if token:
  print("✅ Token acquired:", token)
else:
  print("❌ Token acquisition failed.")
```
💡 After the user authenticates in the browser, the script will prompt for the code and state values from the redirect URL. Just copy them from the browser and paste them when prompted.

## 📚 API Reference

### Authentication & Token Retrieval

#### `get_access_token_with_interactive_device_flow(client_id, issuer, scope="openid", min_ttl=60)`

Attempts to reuse a cached access token or refresh it using a refresh token (RFC 6749 §6).  
If neither is valid or available, it initiates the Device Authorization Grant flow (RFC 8628).

**Parameters:**
- `client_id` *(str)* - OAuth 2.0 client ID.
- `issuer` *(str)* - OIDC issuer URL.
- `scope` *(str or list)* - Requested scopes (default: `"openid"`).
- `min_ttl` *(int)* - Required minimum time-to-live (in seconds) for access token (default: `60`).

**Returns:**
- `access_token` *(str or None)* - Valid access token or `None` if flow fails.

#### `get_access_token_with_interactive_authorization_code_flow(client_id, issuer, redirect_uri, scope="openid", min_ttl=60, use_pkce=True, client_secret=None)`

Attempts to reuse a cached access token or refresh it using a refresh token (RFC 6749 §6).  
If neither is available or valid, it initiates the **Authorization Code Grant** (RFC 6749 §4.1) with optional **PKCE S256** (RFC 7636).  
The function prints a URL that must be opened in a browser to authorize the client.

To complete the flow, you must extract the `code` and `state` from the redirect response and pass them to `complete_authorization_code_exchange(...)`.

**Parameters:**
- `client_id` *(str)* - OAuth 2.0 client ID.
- `issuer` *(str)* - OIDC issuer URL.
- `redirect_uri` *(str)* - Redirect URI registered with the client.
- `scope` *(str or list)* - Requested scopes (default: `"openid"`).
- `min_ttl` *(int)* - Required minimum time-to-live (in seconds) for access token (default: `60`).
- `use_pkce` *(bool)* - Whether to use PKCE with SHA-256 (S256) as the code challenge method. Recommended and enabled by default.
- `client_secret` *(str or None)* - Client secret (required for confidential clients).

**Returns:**
- A valid `access_token` *(str)* if one was found in cache or successfully refreshed.
- `None` if the flow was initiated and user interaction is required.  The access token will be available after calling `complete_authorization_code_exchange(...)`.

#### `complete_authorization_code_exchange(client_id, issuer, scope, authorization_code, state, client_secret=None)`

Completes the **Authorization Code Grant** by exchanging an authorization code for access and refresh tokens.  
It automatically verifies `state` against pending flow metadata, and stores the tokens in the local token store.

Supports both public and confidential clients, with or without **PKCE** (RFC 7636).

**Parameters:**
- `client_id` *(str)* - OAuth 2.0 client ID.
- `issuer` *(str)* - OIDC issuer URL.
- `scope` *(str or list)* - Scope used during initiation (must match).
- `authorization_code` *(str)* - Code received after user authorization.
- `state` *(str)* - State returned by the authorization server.
- `client_secret` *(str or None)* - Client secret (required for confidential clients).

**Returns:**
- `access_token` *(str or None)* - The retrieved access token, or `None` on error.

### Token Introspection

#### `introspect_token(token, client_id, client_secret, issuer=None)`

Performs token introspection (RFC 7662) using the authorization server's introspection endpoint.

**Parameters:**
- `token` *(str)* - Access or refresh token to introspect.
- `client_id` *(str)* - OAuth 2.0 client ID.
- `client_secret` *(str)* - OAuth 2.0 client secret.
- `issuer` *(str or None)* - OIDC issuer URL. If `None`, extracted from the token (if possible).

**Returns:**
- Parsed introspection response *(dict)* or `None`.


### Token Revocation

#### `revoke_access_token(client_id, issuer, scope="openid", client_secret=None)`

Revokes an access token (RFC 7009).

**Parameters:**
- `client_id` *(str)* - OAuth 2.0 client ID.
- `issuer` *(str)* - OIDC issuer.
- `scope` *(str or list)* - Scope associated with the token (default: `"openid"`).
- `client_secret` *(str or None)* - OAuth 2.0 client secret.

**Returns:**
- `bool` - True if the access token expired or was successfully revoked, False otherwise. Logs success/failure.


#### `revoke_refresh_token(client_id, issuer, scope="openid", client_secret=None)`

Revokes a refresh token (RFC 7009).

**Parameters:**
- `client_id` *(str)* - OAuth 2.0 client ID.
- `issuer` *(str)* - OIDC issuer.
- `scope` *(str or list)* - Scope associated with the token (default: `"openid"`).
- `client_secret` *(str or None)* - OAuth 2.0 client secret.

**Returns:**
- `bool` - True if the refresh token was successfully revoked, False otherwise. Logs success/failure.


### Token Store Management

#### `clear_token_store_entry(client_id, issuer, scope=None, revoke_offline=True, revoke_online=False, remove_on_revoke_fail=False, client_secret=None)`

Removes a token entry from the local token store.

**Parameters:**
- `client_id` *(str)* - OAuth 2.0 client ID.
- `issuer` *(str)* - OIDC issuer.
- `scope` *(str or list or None)* - Specific scope entry to remove (optional).
- `revoke_offline` *(bool)* - Revoke tokens with `offline_access` before deletion (default: `True`).
- `revoke_online` *(bool)* - Revoke other tokens (non-offline) before deletion (default: `False`).
- `remove_on_revoke_fail` *(bool)* - If `False`, token is not removed if revocation fails (default: `False`).
- `client_secret` *(str or None)* - OAuth 2.0 client secret.

**Returns:**
- `bool` - Whether the entry was successfully removed.


#### `clear_token_store(revoke_offline=True, revoke_online=False, remove_on_revoke_fail=False)`

Clears the entire token store, optionally revoking tokens.
Please note that revocation of tokens issued to confidential clients may fail unless credentials are provided. If you need to revoke such entries, use `clear_token_store_entry(..., client_secret=...)` per client. 

**Parameters:**
- `revoke_offline` *(bool)* - Attempt to revoke all refresh tokens with `offline_access` (default: `True`).
- `revoke_online` *(bool)* - Attempt to revoke all online (non-offline) refresh tokens (default: `False`).
- `remove_on_revoke_fail` *(bool)* - If `False`, tokens are not removed if revocation fails (default: `False`).

**Returns:**
- None. Logs success or errors.


#### `list_token_store_entries()`

Lists all stored token entries with metadata and expiration info.

**Parameters:**
- None.

**Returns:**
- None. Prints list to stdout.

## 📄 Token Store Format

Tokens are stored as JSON under:

```bash
~/.pyauthflow_token_store.json
```

Structure:

```json
{
  "<hash(client_id|issuer)>": {
    "<scope_key>": {
      "access_token": "...",
      "refresh_token": "...",
      "client_id": "...",
      "issuer": "...",
      "_pending_auth_code": {
        "redirect_uri": "...",
        "state": "...",
        "code_verifier": "..."
      }
    }
  }
}
```
Entries with _pending_auth_code indicate that an Authorization Code Grant flow is in progress and not yet completed.

## ✅ Standards Compliance

- **OAuth 2.0 Authorization Framework** - [RFC 6749](https://tools.ietf.org/html/rfc6749)
- **Device Authorization Grant** - [RFC 8628](https://tools.ietf.org/html/rfc8628)
- **PKCE** - [RFC 7636](https://tools.ietf.org/html/rfc7636)
- **Token Revocation** - [RFC 7009](https://tools.ietf.org/html/rfc7009)
- **Token Introspection** - [RFC 7662](https://tools.ietf.org/html/rfc7662)

## 📢 Notes

- 🔧 Designed specifically for **command-line tools**, **Jupyter notebooks**, and other **headless or interactive scripting environments**.
- 🌐 During the Device Authorization flow, the library uses `verification_uri_complete` when available for smoother user experience. Falls back to `verification_uri` and `user_code` entry if needed - in line with **RFC 8628 §3.3**.
- 🧭 Supports interactive Authorization Code Grant with redirect-based browser login - **RFC 6749 §4.1**. 💡 Requires manual copy-paste of the code and state query parameters from the browser redirect back into the script or notebook to complete the flow. Useful when the Authorization Server does not support the Device Authorization Grant.
- 🔒 Uses Proof Key for Code Exchange (PKCE) by default to protect against authorization code injection attacks. Automatically applies S256 code challenge method - **RFC 7636**.
- 🧷 Stores code_verifier and state securely in memory (in the token store) for later validation during code exchange. 
- 🧪 Validates returned state parameter to defend against CSRF-style attacks during code exchange.
- 🔒 All tokens are stored **locally only** in a JSON file under the user's home directory (`~/.pyauthflow_token_store.json`).  
  No tokens are ever transmitted, synchronized, or stored remotely by this library.
- ✳️ When requesting the offline_access scope (as per **OIDC Core §11**), the library automatically adds the prompt=consent parameter to ensure a refresh token is granted (per provider expectations).
- 🧠 Automatically deduplicates scopes and sorts them to normalize token cache lookups.
- 📦 The token store can hold multiple token sets - one for each `(client_id, issuer, scope)` combination.

## 🛡️ License

```
Copyright 2025 Tomasz Kuczyński (https://github.com/docentt)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy at:

    http://www.apache.org/licenses/LICENSE-2.0
```

See [`LICENSE`](LICENSE) for details.

## 🌐 Links

- RFC 8628 (Device Flow): https://datatracker.ietf.org/doc/html/rfc8628
- RFC 6749 (OAuth 2.0): https://datatracker.ietf.org/doc/html/rfc6749
- RFC 7009 (Revocation): https://datatracker.ietf.org/doc/html/rfc7009
- RFC 7662 (Introspection): https://datatracker.ietf.org/doc/html/rfc7662
- RFC 7636 (PKCE): https://datatracker.ietf.org/doc/html/rfc7636
