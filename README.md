# PyAuthFlow - OAuth 2.0 / OIDC Token Manager

**PyAuthFlow** is a lightweight, zero-dependency Python module for managing OAuth 2.0 and OpenID Connect (OIDC) tokens.

It supports device authorization, token refresh, revocation, introspection, and secure local storage - all with a clean, user-friendly interface.

Designed for interactive environments like Jupyter notebooks, CLI tools, or lightweight scripts, PyAuthFlow helps developers handle OAuth flows without the need for full web frameworks.

## ✨ Features

- 🔐 **Device Authorization Grant** (a.k.a. *Device Flow*)  
  Enables headless or CLI-based authentication.  
  **[RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)**

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

### Option 1 – 📥 Download the file directly

```bash
curl -O https://raw.githubusercontent.com/docentt/pyauthflow/main/token_manager.py
```

### Option 2 – 🧬 Clone the full repository

```bash
git clone https://github.com/docentt/pyauthflow.git
```

### Option 3 – 📓 Load in Jupyter Notebook

Paste this into a notebook cell:

```python
!git clone https://github.com/docentt/pyauthflow.git
import sys
sys.path.insert(0, "pyauthflow")
```

## 🚀 Usage Example

```python
from token_manager import get_access_token_with_interactive_device_flow

client_id = "your-client-id"
issuer = "https://your.issuer.com"
scope = "openid profile email"

token = get_access_token_with_interactive_device_flow(client_id, issuer, scope)

if token:
    print("✅ Access token:", token)
```
✅ This handles caching, refresh, and the full device flow transparently.

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

#### `revoke_access_token(client_id, issuer, scope)`

Revokes an access token (RFC 7009).

**Parameters:**
- `client_id` *(str)* - OAuth 2.0 client ID.
- `issuer` *(str)* - OIDC issuer.
- `scope` *(str or list)* - Scope associated with the token.

**Returns:**
- None. Logs success/failure.


#### `revoke_refresh_token(client_id, issuer, scope)`

Revokes a refresh token (RFC 7009).

**Parameters:**
- `client_id` *(str)* - OAuth 2.0 client ID.
- `issuer` *(str)* - OIDC issuer.
- `scope` *(str or list)* - Scope associated with the token.

**Returns:**
- None. Logs success/failure.


### Token Store Management

#### `clear_token_store_entry(client_id, issuer, scope=None, revoke_offline=True, revoke_online=False, remove_on_revoke_fail=False)`

Removes a token entry from the local token store.

**Parameters:**
- `client_id` *(str)* - OAuth 2.0 client ID.
- `issuer` *(str)* - OIDC issuer.
- `scope` *(str or list or None)* - Specific scope entry to remove (optional).
- `revoke_offline` *(bool)* - Revoke tokens with `offline_access` before deletion (default: `True`).
- `revoke_online` *(bool)* - Revoke other tokens (non-offline) before deletion (default: `False`).
- `remove_on_revoke_fail` *(bool)* - If `False`, token is not removed if revocation fails (default: `False`).

**Returns:**
- `bool` - Whether the entry was successfully removed.


#### `clear_token_store(revoke_offline=True, revoke_online=False, remove_on_revoke_fail=False)`

Clears the entire token store, optionally revoking tokens.

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
      "issuer": "..."
    }
  }
}
```

## ✅ Standards Compliance

- **OAuth 2.0 Authorization Framework** - [RFC 6749](https://tools.ietf.org/html/rfc6749)
- **Device Authorization Grant** - [RFC 8628](https://tools.ietf.org/html/rfc8628)
- **Token Revocation** - [RFC 7009](https://tools.ietf.org/html/rfc7009)
- **Token Introspection** - [RFC 7662](https://tools.ietf.org/html/rfc7662)

## 📢 Notes

- 🔧 Designed specifically for **command-line tools**, **Jupyter notebooks**, and other **headless or interactive scripting environments**.
- 🌐 Leverages `verification_uri_complete` when available for smoother user experience. Falls back to `verification_uri` and `user_code` entry if needed - in line with **RFC 8628 §3.3**.
- 🔒 All tokens are stored **locally only** in a JSON file under the user's home directory (`~/.pyauthflow_token_store.json`).  
  No tokens are ever transmitted, synchronized, or stored remotely by this library.
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
