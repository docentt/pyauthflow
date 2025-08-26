# token_manager.py

"""
PyAuthFlow - OAuth 2.0 / OIDC Token Manager

Copyright 2025 Tomasz Kuczyński (https://github.com/docentt)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import os
import json
import time
import requests
from pathlib import Path
import secrets
import urllib.parse
import hashlib
import base64
from datetime import datetime

# Token store path
TOKEN_STORE = Path.home() / ".pyauthflow_token_store.json"

DEFAULT_MIN_TTL = 60  # Minimal TTL in seconds
DEFAULT_SCOPE = "openid"

def _token_key(client_id, issuer):
    raw_key = f"{client_id}|{issuer}"
    return hashlib.sha256(raw_key.encode()).hexdigest()

def _scope_key(scope):
    if isinstance(scope, str):
        scope = scope.strip().split()
    return " ".join(sorted(set(scope)))

def _load_store():
    if TOKEN_STORE.exists():
        with open(TOKEN_STORE, 'r') as f:
            return json.load(f)
    return {}

def _save_store(store):
    def opener(path, flags):
        return os.open(path, flags, 0o600)

    with open(TOKEN_STORE, 'w', opener=opener) as f:
        json.dump(store, f)

def _decode_jwt_payload(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        return json.loads(decoded_bytes)
    except Exception:
        return None

def _is_token_valid(token, min_ttl):
    payload = _decode_jwt_payload(token)
    if not payload or "exp" not in payload:
        return False
    exp = payload["exp"]
    return (exp - int(time.time())) >= min_ttl

def _refresh_access_token(client_id, refresh_token, token_endpoint, client_secret=None):
    try:
        auth = (client_id, client_secret) if client_secret is not None else None

        resp = requests.post(token_endpoint, data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token
        }, auth=auth)
        if resp.ok:
            data = resp.json()
            return data.get("access_token"), data.get("refresh_token"), data.get("scope")
        else:
            print(f"⚠️ Refresh grant failed (HTTP {resp.status_code}): {resp.text}")
    except Exception as e:
        print(f"❌ Error during refresh token request: {str(e)}")
    return None, None, None

def discover_oidc_metadata(issuer):
    try:
        discovery_url = f"{issuer}/.well-known/openid-configuration"
        return requests.get(discovery_url).json()
    except Exception as e:
        print(f"❌ Failed to retrieve discovery document: {str(e)}")
        return None

def get_access_token_with_interactive_device_flow(client_id, issuer, scope=DEFAULT_SCOPE, min_ttl=DEFAULT_MIN_TTL):
    try:
        key = _token_key(client_id, issuer)
        requested_scope_key = _scope_key(scope)

        store = _load_store()
        client_entry = store.get(key, {})
        entry = client_entry.get(requested_scope_key, {})

        refresh_token = entry.get("refresh_token")
        cached_token = entry.get("access_token")

        if cached_token and _is_token_valid(cached_token, min_ttl):
            print("ℹ️ Using cached access token.")
            return cached_token

        discovery = discover_oidc_metadata(issuer)
        if not discovery:
            return None

        token_endpoint = discovery.get("token_endpoint")
        device_endpoint = discovery.get("device_authorization_endpoint")

        if not token_endpoint or not device_endpoint:
            print("❌ Missing token or device endpoint in discovery metadata.")
            return None

        def perform_device_flow():
            try:
                resp = requests.post(device_endpoint, data={"client_id": client_id, "scope": requested_scope_key})

                if not resp.ok:
                    try:
                        data = resp.json()
                        error = data.get("error", f"HTTP {resp.status_code}")
                        description = data.get("error_description", resp.text)
                    except Exception:
                        error = f"HTTP {resp.status_code}"
                        description = resp.text
                    print(f"❌ Device flow initiation failed: {error} - {description}")
                    return None, None, None

                data = resp.json()
                required_fields = ["device_code", "user_code", "verification_uri", "expires_in"]
                if not all(field in data for field in required_fields):
                    print("❌ Missing expected fields in device flow response.")
                    return None, None, None

                print("\n🔐 Authorize Access")
                print("----------------------------------------")
                print("You are about to interact with an authorization server.")
                print("There, you will be asked to grant access permissions.")
                print("This allows the system to act on your behalf using delegated access.")
                print("Be patient - a slight delay may occur between granting consent and authorization.")
                print("Proceed only if you trust this application.\n")

                print("To authorize:")
                print(f"➡️  Visit: {data['verification_uri']}")
                print(f"🔢 Then enter the user code: {data['user_code']}")

                if "verification_uri_complete" in data:
                    print("------ or simply ------")
                    print(f"➡️  Open: {data['verification_uri_complete']}")

                print(f"\n⌛ You have approximately {int(data['expires_in'] / 60)} minutes to complete the authorization.")

                device_code = data["device_code"]
                interval = data.get("interval", 5)
                expires_in = data["expires_in"]

                for elapsed in range(expires_in):
                    if elapsed % interval == 0:
                        try:
                            poll = requests.post(token_endpoint, data={
                                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                "device_code": device_code,
                                "client_id": client_id
                            })
                            if poll.status_code == 200:
                                t = poll.json()
                                granted_scope = t.get("scope", requested_scope_key)
                                return t.get("access_token"), t.get("refresh_token"), granted_scope
                            elif poll.status_code == 400:
                                try:
                                    err = poll.json().get("error")
                                    if err == "authorization_pending":
                                        pass
                                    elif err == "slow_down":
                                        interval += 1
                                        print("⏳ Server requested slower polling. Increasing interval.")
                                    elif err == "access_denied":
                                        print("❌ Access was denied by user.")
                                        return None, None, None
                                    elif err == "expired_token":
                                        print("❌ Authorization not completed in time.")
                                        return None, None, None
                                    else:
                                        print(f"❌ Unexpected polling error: {err}")
                                        return None, None, None
                                except Exception:
                                    print("❌ Failed to parse polling error response.")
                                    return None, None, None
                        except Exception as e:
                            print(f"❌ Polling error: {str(e)}")
                            return None, None, None
                    remaining = expires_in - elapsed
                    print(f"⏳ Waiting... {remaining}s remaining", end='\r')
                    time.sleep(1)

                print("\n❌ Timeout: Authorization not completed in time.")
                return None, None, None
            except Exception as e:
                print(f"❌ Error during device flow: {str(e)}")
                return None, None, None

        if refresh_token:
            access_token, new_refresh, actual_scope = _refresh_access_token(client_id , refresh_token, token_endpoint)
            if access_token:
                effective_scope_key = _scope_key(actual_scope or requested_scope_key)
                if key not in store:
                    store[key] = {}
                store[key][effective_scope_key] = {
                    "refresh_token": new_refresh,
                    "access_token": access_token,
                    "client_id": client_id,
                    "issuer": issuer
                }
                print("🔄 Tokens refreshed successfully.")
                _save_store(store)
                return access_token

        access_token, refresh_token, actual_scope = perform_device_flow()
        if access_token:
            effective_scope_key = _scope_key(actual_scope or requested_scope_key)
            if key not in store:
                store[key] = {}
            store[key][effective_scope_key] = {
                "access_token": access_token,
                "client_id": client_id,
                "issuer": issuer
            }
            if refresh_token:
                store[key][effective_scope_key]["refresh_token"] = refresh_token

            print("✅ Tokens acquired and stored successfully.")
            _save_store(store)
            return access_token

        print("❌ Could not retrieve tokens.")
        return None
    except Exception as e:
        print(str(e))
        return None

def get_access_token_with_interactive_authorization_code_flow(client_id, issuer, redirect_uri, scope=DEFAULT_SCOPE, min_ttl=DEFAULT_MIN_TTL, use_pkce=True, client_secret=None):
    try:
        key = _token_key(client_id, issuer)
        requested_scope_key = _scope_key(scope)

        store = _load_store()
        client_entry = store.get(key, {})
        entry = client_entry.get(requested_scope_key, {})

        refresh_token = entry.get("refresh_token")
        cached_token = entry.get("access_token")

        if cached_token and _is_token_valid(cached_token, min_ttl):
            print("ℹ️ Using cached access token.")
            return cached_token

        discovery = discover_oidc_metadata(issuer)
        if not discovery:
            return None

        token_endpoint = discovery.get("token_endpoint")
        authorization_endpoint = discovery.get("authorization_endpoint")

        if not token_endpoint:
            print("❌ Missing token endpoint in discovery metadata.")
            return None

        if refresh_token:
            access_token, new_refresh, actual_scope = _refresh_access_token(client_id , refresh_token, token_endpoint, client_secret)
            if access_token:
                effective_scope_key = _scope_key(actual_scope or requested_scope_key)
                if key not in store:
                    store[key] = {}
                store[key][effective_scope_key] = {
                    "refresh_token": new_refresh,
                    "access_token": access_token,
                    "client_id": client_id,
                    "issuer": issuer
                }
                print("🔄 Tokens refreshed successfully.")
                _save_store(store)
                return access_token

        if not authorization_endpoint:
            print("❌ No authorization_endpoint in OIDC discovery.")
            return None

        state = secrets.token_urlsafe(16)
        code_verifier = code_challenge = None

        if use_pkce:
            code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b"=").decode()

        store.setdefault(key, {})
        store[key].setdefault(requested_scope_key, {})
        store[key][requested_scope_key]["_pending_auth_code"] = {
            "redirect_uri": redirect_uri,
            "state": state
        }

        if code_verifier:
            store[key][requested_scope_key]["_pending_auth_code"]["code_verifier"] = code_verifier

        _save_store(store)

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": requested_scope_key,
            "state": state
        }

        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        if "offline_access" in requested_scope_key.split():
            params["prompt"] = "consent"

        auth_url = f"{authorization_endpoint}?{urllib.parse.urlencode(params)}"

        print("\n🔐 Authorize Access via Browser")
        print("----------------------------------------")
        print("Open the following URL in your browser to authorize:")
        print(f"➡️  {auth_url}")
        print("\nAfter completing the authorization, you will be redirected to:")
        print(f"{redirect_uri}?code=...&state=...")
        print("Use the code and state to complete the token exchange.\n")

        return None

    except Exception as e:
        print(f"❌ Error initiating authorization code flow: {str(e)}")
        return None

def complete_authorization_code_exchange(client_id, issuer, scope, authorization_code, state, client_secret=None):
    try:
        store = _load_store()
        key = _token_key(client_id, issuer)
        requested_scope_key = _scope_key(scope)

        entry = store.get(key, {}).get(requested_scope_key)
        if not entry or "_pending_auth_code" not in entry:
            print("❌ No pending authorization code flow found for given client and scope")
            return None

        pending = entry["_pending_auth_code"]
        redirect_uri = pending.get("redirect_uri")
        code_verifier = pending.get("code_verifier")
        expected_state = pending.get("state")

        if not redirect_uri:
            print("❌ Missing redirect URI in pending state.")
            return None

        if expected_state is None:
            print("❌ Missing stored state in pending authorization.")
            return None

        if state != expected_state:
            print("❌ State mismatch! Potential CSRF or tampering detected.")
            return None

        discovery = discover_oidc_metadata(issuer)
        if not discovery:
            return None

        token_endpoint = discovery.get("token_endpoint")
        if not token_endpoint:
            print("❌ No token endpoint found in discovery metadata.")
            return None

        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": redirect_uri,
            "client_id": client_id
        }

        if code_verifier:
            data["code_verifier"] = code_verifier

        auth = (client_id, client_secret) if client_secret else None

        resp = requests.post(token_endpoint, data=data, auth=auth)

        if resp.status_code != 200:
            print(f"❌ Token exchange failed (HTTP {resp.status_code}): {resp.text}")
            return None

        token_data = resp.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        granted_scope = token_data.get("scope", requested_scope_key)
        effective_scope_key = _scope_key(granted_scope)

        if not access_token:
            print("❌ Token response missing required field: access_token.")
            return None

        store.setdefault(key, {})
        entry_to_store = {
            "access_token": access_token,
            "client_id": client_id,
            "issuer": issuer
        }
        if refresh_token:
            entry_to_store["refresh_token"] = refresh_token
        else:
            print("ℹ️ No refresh_token returned by authorization server; token refresh will not be possible.")

        store[key][effective_scope_key] = entry_to_store

        if "_pending_auth_code" in store[key].get(requested_scope_key, {}):
            del store[key][requested_scope_key]["_pending_auth_code"]
            if not store[key][requested_scope_key]:
                del store[key][requested_scope_key]

        _save_store(store)
        print("✅ Authorization code exchanged and tokens stored.")
        return access_token

    except Exception as e:
        print(f"❌ Error during authorization code exchange: {str(e)}")
        return None

def introspect_token(token, client_id, client_secret, issuer=None):
    try:
        if not issuer:
            payload = _decode_jwt_payload(token)
            if not payload or "iss" not in payload:
                print("❌ Cannot introspect: 'issuer' not provided and not found in token.")
                return None
            issuer = payload["iss"]

        discovery = discover_oidc_metadata(issuer)
        if not discovery:
            return None

        introspection_endpoint = discovery.get("introspection_endpoint")
        if not introspection_endpoint:
            print("❌ No introspection endpoint provided by discovery document.")
            return None

        resp = requests.post(
            introspection_endpoint,
            data={"token": token},
            auth=(client_id, client_secret)
        )

        if resp.status_code == 200:
            result = resp.json()
            print("✅ Introspection result:")
            print(json.dumps(result, indent=2))
            return result
        else:
            print(f"⚠️ Introspection failed (HTTP {resp.status_code}): {resp.text}")
            return None
    except Exception as e:
        print(f"❌ Failed to introspect token: {str(e)}")
        return None

def revoke_access_token(client_id, issuer, scope=DEFAULT_SCOPE, client_secret=None):
    try:
        store = _load_store()
        key = _token_key(client_id, issuer)
        scope_key = _scope_key(scope)

        if key not in store or scope_key not in store[key]:
            print("ℹ️ No matching entry found.")
            return False

        entry = store[key][scope_key]

        access_token = entry.get("access_token")
        if not access_token:
            print("ℹ️ No access token found for given client and scope.")
            return False

        payload = _decode_jwt_payload(access_token)
        if payload:
            exp = payload.get("exp")
            if exp and int(time.time()) >= exp:
                print("ℹ️ Access token is already expired.")
                entry.pop("access_token", None)
                store[key][scope_key] = entry
                _save_store(store)
                return True

        discovery = discover_oidc_metadata(issuer)
        if not discovery:
            return False

        revocation_endpoint = discovery.get("revocation_endpoint")
        if not revocation_endpoint:
            print("⚠️ No revocation endpoint provided by discovery document.")
            return False

        auth = (client_id, client_secret) if client_secret else None
        data = {
            "token": access_token,
            "token_type_hint": "access_token",
        }
        if not client_secret:
            data["client_id"] = client_id

        resp = requests.post(revocation_endpoint, data=data, auth=auth)

        if resp.status_code == 200:
            print("✅ Access token revoked at authorization server.")
            entry.pop("access_token", None)
            store[key][scope_key] = entry
            _save_store(store)
            return True
        else:
            print(f"⚠️ Failed to revoke access token: {resp.status_code} {resp.text}")
            return False
    except Exception as e:
        print(f"❌ Failed to revoke access token: {str(e)}")
        return False

def revoke_refresh_token(client_id, issuer, scope=DEFAULT_SCOPE, client_secret=None):
    try:
        store = _load_store()
        key = _token_key(client_id, issuer)
        scope_key = _scope_key(scope)

        if key not in store or scope_key not in store[key]:
            print("ℹ️ No matching entry found.")
            return False

        entry = store[key][scope_key]
        refresh_token = entry.get("refresh_token")
        if not refresh_token:
            print("ℹ️ No refresh token found for given client and scope.")
            return False

        discovery = discover_oidc_metadata(issuer)
        if not discovery:
            return False

        revocation_endpoint = discovery.get("revocation_endpoint")
        if not revocation_endpoint:
            print("⚠️ No revocation endpoint provided by discovery document.")
            return False

        auth = (client_id, client_secret) if client_secret else None
        data = {
            "token": refresh_token,
            "token_type_hint": "refresh_token",
        }
        if not client_secret:
            data["client_id"] = client_id

        resp = requests.post(revocation_endpoint, data=data, auth=auth)

        if resp.status_code == 200:
            print("✅ Refresh token revoked at authorization server.")
            del store[key][scope_key]
            if not store[key]:
                del store[key]
            _save_store(store)
            return True
        else:
            print(f"⚠️ Failed to revoke refresh token: {resp.status_code} {resp.text}")
            return False
    except Exception as e:
        print(f"❌ Failed to revoke refresh token: {str(e)}")
        return False

def _remove_scope_entry(entries, scope_key, client_id, revoke_offline, revoke_online, remove_on_revoke_fail, discovery, client_secret=None):
    entry = entries.get(scope_key)
    if not entry:
        return False

    scopes_set = set(scope_key.split())
    has_offline = "offline_access" in scopes_set
    should_revoke = (has_offline and revoke_offline) or (not has_offline and revoke_online)
    revoke_ok = True

    if should_revoke:
        revoke_ok = False
        if discovery:
            revocation_endpoint = discovery.get("revocation_endpoint")

            if revocation_endpoint:
                token_to_revoke = None
                token_type_hint = None

                if "refresh_token" in entry:
                    token_to_revoke = entry.get("refresh_token")
                    token_type_hint = "refresh_token"
                elif "access_token" in entry:
                    token_to_revoke = entry.get("access_token")
                    token_type_hint = "access_token"

                if token_to_revoke:
                    auth = (client_id, client_secret) if client_secret else None
                    data = {
                        "token": token_to_revoke,
                        "token_type_hint": token_type_hint,
                    }
                    if not client_secret:
                        data["client_id"] = client_id

                    resp = requests.post(revocation_endpoint, data=data, auth=auth)
                    if resp.status_code == 200:
                        revoke_ok = True
                    else:
                        print(f"⚠️ Failed to revoke {token_type_hint} for scope '{scope_key}': {resp.status_code} {resp.text}")

    if revoke_ok or remove_on_revoke_fail:
        if scope_key in entries:
            del entries[scope_key]
        return True
    return False

def clear_token_store_entry(client_id, issuer, scope=None, revoke_offline=True, revoke_online=False, remove_on_revoke_fail=False, client_secret=None):
    try:
        store = _load_store()
        key = _token_key(client_id, issuer)
        if key not in store:
            print("ℹ️ No matching entry found.")
            return False

        entries = store[key]
        removed_scopes = []
        original_scopes = list(entries.keys())

        discovery = discover_oidc_metadata(issuer) if (revoke_offline or revoke_online) else None

        if scope:
            requested_scope_key = _scope_key(scope)
            entry = entries.get(requested_scope_key)
            if not entry:
                print(f"ℹ️ No entry found for the specified scope: '{requested_scope_key}'")
                return False
            if _remove_scope_entry(entries, requested_scope_key, client_id, revoke_offline, revoke_online, remove_on_revoke_fail, discovery, client_secret):
                removed_scopes.append(requested_scope_key)
        else:
            for scope_key in original_scopes:
                if _remove_scope_entry(entries, scope_key, client_id, revoke_offline, revoke_online, remove_on_revoke_fail, discovery, client_secret):
                    removed_scopes.append(scope_key)

        if scope:
            success = bool(removed_scopes)
        else:
            success = len(removed_scopes) == len(original_scopes)

        if removed_scopes:
            if not entries:
                del store[key]
            _save_store(store)
            if scope:
                print(f"✅ Removed token entry for scope: '{removed_scopes[0]}'")
            elif success:
                print("✅ Removed all requested token entries.")
            else:
                print("⚠️ Removed some token entries, but others failed.")
        else:
            print("ℹ️ No token entries removed.")

        return success

    except Exception as e:
        print(f"❌ Failed to clear token entry: {str(e)}")
        return False

def clear_token_store(revoke_offline=True, revoke_online=False, remove_on_revoke_fail=False):
    try:
        store = _load_store()
        if not store:
            print("ℹ️ No token store file found.")
            return

        for key, client_entry in list(store.items()):
            sample_scope = next(iter(client_entry.values()), {})
            client_id = sample_scope.get("client_id")
            issuer = sample_scope.get("issuer")
            if client_id and issuer:
                clear_token_store_entry(
                    client_id,
                    issuer,
                    revoke_offline=revoke_offline,
                    revoke_online=revoke_online,
                    remove_on_revoke_fail=remove_on_revoke_fail
                )

        store = _load_store()
        if not store:
            print("✅ Entire token store cleared.")
        else:
            print("⚠️ Some entries could not be removed from token store.")

    except Exception as e:
        print(f"❌ Failed to clear token store: {str(e)}")

def list_token_store_entries():
    try:
        store = _load_store()
        if not store:
            print("ℹ️ No tokens stored.")
            return

        print("🔐 Stored token entries:")
        for key, scopes in store.items():
            for scope_key, entry in scopes.items():
                client = entry.get("client_id", "unknown")
                iss = entry.get("issuer", "unknown")
                print(f" - client_id: {client}")
                print(f"   issuer: {iss}")
                print(f"   scope: {scope_key}")

                refresh_token = entry.get("refresh_token")
                if refresh_token:
                    payload = _decode_jwt_payload(refresh_token)
                    if payload and "exp" in payload:
                        exp = payload["exp"]
                        exp_str = datetime.utcfromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S UTC')
                        print(f"   refresh_token exp: {exp} ({exp_str})")
                    else:
                        print("   refresh_token exp: ? (could not decode refresh token)")
                else:
                    print("   refresh_token: <missing>")

                access_token = entry.get("access_token")
                if access_token:
                    payload = _decode_jwt_payload(access_token)
                    if payload:
                        scopes = payload.get("scope", "n/a")
                        audience = payload.get("aud", "n/a")
                    else:
                        scopes = audience = "? (Could not decode access token)"
                    print(f"   access_token scope: {scopes}")
                    print(f"   access_token audience: {audience}")
    except Exception as e:
        print(f"❌ Failed to list token entries: {str(e)}")
