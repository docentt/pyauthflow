# __init__.py

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

from .token_manager import (
    discover_oidc_metadata,
    get_access_token_with_interactive_device_flow,
    get_access_token_with_interactive_authorization_code_flow,
    complete_authorization_code_exchange,
    clear_token_store,
    clear_token_store_entry,
    list_token_store_entries,
    revoke_access_token,
    revoke_refresh_token,
    introspect_token
)

__all__ = [
    "discover_oidc_metadata",
    "get_access_token_with_interactive_device_flow",
    "get_access_token_with_interactive_authorization_code_flow",
    "complete_authorization_code_exchange",
    "clear_token_store",
    "clear_token_store_entry",
    "list_token_store_entries",
    "revoke_access_token",
    "revoke_refresh_token",
    "introspect_token"
]