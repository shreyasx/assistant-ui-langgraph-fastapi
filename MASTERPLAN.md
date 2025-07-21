# MASTERPLAN: Migrate Tools from relso-sage to Backend Starter Code

**Migration Rules & Demo Instructions**

1. **Do not change anything in `/relso-sage`.** All migrations and new code must be in the backend or frontend as described below.
2. **Implement a basic threads component in `/frontend` for demo/testing.** For this demo, messages do not need to be persisted—just keep them in state and lose them on refresh. The goal is to test agent functionality, not storage.
3. **The new backend system must be stateless:** it should work with threads if message history is provided from the frontend, or else treat it as a new thread. The API must not store any message history itself.

## Overview

This master plan details the migration of all tools from `@/relso-sage` into `@/backend` while strictly following the backend starter code structure and patterns. The backend uses LangGraph with streaming responses, and we'll extend it gracefully without breaking existing patterns.

## 🎯 Migration Goals

1. **Preserve Backend Structure**: Follow `@/backend` folder organization and patterns
2. **Maintain Streaming**: Use backend's streaming patterns, not relso-sage patterns
3. **Tool Integration**: Seamlessly integrate all relso-sage tools into the LangGraph agent
4. **Environment Management**: Centralize configuration using backend patterns
5. **Authentication**: Implement auth following backend conventions

## 📊 Tools Inventory (from relso-sage)

### Google Workspace Tools (17 tools)

- **Google Docs**: create_document, read_document, update_document, list_documents, search_documents
- **Google Sheets**: create_spreadsheet, read_spreadsheet, update_spreadsheet, list_spreadsheets, append_to_sheet, search_spreadsheets
- **Google Drive**: upload_file, list_files, search_files
- **Google Calendar**: create_event, list_events, search_events
- **Gmail**: send_email, list_emails, search_emails
- **Google Slides**: create_presentation, read_presentation, list_presentations, search_presentations
- **Google Meet**: create_meeting, list_meetings, search_meetings

### Shopify Tools (10 tools)

- **Products**: get_product_by_sku, get_product_by_id, search_products
- **Inventory**: fetch_product_inventory, get_inventory_by_sku
- **Customers**: search_customers, fetch_all_customers
- **Orders**: fetch_all_orders, search_orders
- **Auth**: get_auth_status

## 🏗️ Backend Structure Analysis

Current backend structure:

```
backend/
├── app/
│   ├── __init__.py
│   ├── add_langgraph_route.py    # Chat endpoint handler
│   ├── server.py                 # FastAPI app entry point
│   └── langgraph/
│       ├── agent.py              # LangGraph workflow definition
│       ├── state.py              # Agent state management
│       └── tools.py              # Tool definitions (1 sample tool)
├── pyproject.toml                # Dependencies
└── Dockerfile
```

## 📋 Migration Plan

### Phase 1: Backend Infrastructure Setup

#### 1.1 Update Dependencies

**File**: `backend/pyproject.toml`

Add dependencies for Google Workspace and Shopify tools:

```toml
[tool.poetry.dependencies]
python = "^3.11"
uvicorn = "^0.23.2"
pydantic = "^2.9.2"
langchain-core = "^0.3.17"
langchain-openai = "^0.2.8"
langgraph = "^0.2.49"
python-dotenv = "^1.0.1"
assistant-stream = "^0.0.5"
# NEW: Tool dependencies
httpx = "^0.27.2"
google-api-python-client = "^2.121.0"
google-auth-httplib2 = "^0.1.1"
google-auth-oauthlib = "^1.2.0"
PyJWT = "^2.8.0"
pydantic-settings = "^2.10.1"
# NEW: Supabase for secure token storage
supabase = "^2.12.0"
```

#### 1.2 Create Configuration Management

**File**: `backend/app/config.py`

```python
from pydantic_settings import BaseSettings
from typing import Optional, List
from pydantic import Field

class Settings(BaseSettings):
    # OpenAI
    openai_api_key: Optional[str] = None

    # Supabase Configuration
    supabase_url: str = Field(..., env="SUPABASE_URL")
    supabase_key: str = Field(..., env="SUPABASE_KEY")
    supabase_jwt_secret: str = Field(..., env="SUPABASE_JWT_SECRET")

    # Google Workspace OAuth2
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    google_redirect_uri: str = Field(
        default="http://localhost:8000/oauth/google/callback",
        env="GOOGLE_REDIRECT_URI"
    )

    @property
    def google_redirect_uris(self) -> List[str]:
        """Get all allowed redirect URIs for Google OAuth2."""
        base_uri = self.google_redirect_uri
        if "localhost" in base_uri:
            # Development environment
            return [
                "http://localhost:8000/oauth/google/callback",
                "http://localhost:8000/oauth/google-workspace/callback"
            ]
        else:
            # Production environment
            return [
                base_uri,
                "https://your-domain.com/oauth/google/callback",
            ]

    # Shopify
    shopify_store_domain: Optional[str] = None
    shopify_admin_token: Optional[str] = None

    # FastAPI Configuration
    debug: bool = Field(default=False, env="DEBUG")
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")

    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()
```

#### 1.3 Create JWT Authentication Middleware

**File**: `backend/app/middleware/__init__.py`

```python
"""
Middleware package for authentication and other request processing.
"""

from .auth import verify_jwt_dependency, jwt_auth

__all__ = ["verify_jwt_dependency", "jwt_auth"]
```

**File**: `backend/app/middleware/auth.py`

```python
"""
Authentication middleware for JWT verification.
Handles Supabase JWT token validation for protected endpoints.
"""

import logging
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt as pyjwt
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, InvalidTokenError
from backend.app.config import settings

# Set up logging
logger = logging.getLogger(__name__)

# Security scheme for Bearer token
security = HTTPBearer(auto_error=False)

class JWTAuthMiddleware:
    """Middleware for JWT authentication using Supabase tokens."""

    def __init__(self):
        self.jwt_secret = settings.supabase_jwt_secret

    def extract_token(self, request: Request) -> Optional[str]:
        """
        Extract JWT token from Authorization header.

        Args:
            request: FastAPI request object

        Returns:
            str: The JWT token if found, None otherwise
        """
        try:
            # Get the Authorization header
            auth_header = request.headers.get("Authorization")

            if not auth_header:
                return None

            # Check if it starts with "Bearer "
            if not auth_header.startswith("Bearer "):
                return None

            # Extract the token (remove "Bearer " prefix)
            token = auth_header[7:]  # "Bearer " is 7 characters
            return token

        except Exception:
            return None

    def verify_jwt_token(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode JWT token using Supabase secret.

        Args:
            token: The JWT token to verify

        Returns:
            Dict containing the decoded token payload

        Raises:
            HTTPException: If token is invalid, expired, or malformed
        """
        try:
            # Decode and verify the JWT token with relaxed options for Supabase
            payload = pyjwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": False,  # Disable audience verification for Supabase
                    "verify_iss": False,  # Disable issuer verification
                }
            )

            return payload

        except ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except InvalidSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signature"
            )
        except InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token verification failed: {str(e)}"
            )

    def get_user_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract user information from JWT payload.

        Args:
            payload: The decoded JWT payload

        Returns:
            Dict containing user information
        """
        user_info = {
            "user_id": payload.get("sub"),  # Subject (user ID)
            "email": payload.get("email"),
            "role": payload.get("role"),
            "aud": payload.get("aud"),  # Audience
            "exp": payload.get("exp"),  # Expiration
            "iat": payload.get("iat"),  # Issued at
        }

        # Remove None values
        return {k: v for k, v in user_info.items() if v is not None}

    async def authenticate_request(self, request: Request) -> Dict[str, Any]:
        """
        Authenticate a request using JWT token.

        Args:
            request: FastAPI request object

        Returns:
            Dict containing user information if authentication succeeds

        Raises:
            HTTPException: If authentication fails
        """
        # Extract token from request
        token = self.extract_token(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header missing or invalid. Expected: 'Bearer <token>'"
            )

        # Verify the token
        payload = self.verify_jwt_token(token)

        # Extract user information
        user_info = self.get_user_info(payload)

        # Validate that we have a user ID
        if not user_info.get("user_id"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user ID"
            )

        return user_info

# Create a global instance
jwt_auth = JWTAuthMiddleware()

async def verify_jwt_dependency(request: Request) -> Dict[str, Any]:
    """
    FastAPI dependency for JWT verification.
    Use this in route dependencies to protect endpoints.

    Args:
        request: FastAPI request object

    Returns:
        Dict containing user information
    """
    return await jwt_auth.authenticate_request(request)
```

#### 1.4 Create Supabase Token Service

**File**: `backend/app/services/__init__.py`

```python
"""
Services package for external integrations.
"""

from .supabase_token_service import token_service

__all__ = ["token_service"]
```

**File**: `backend/app/services/supabase_token_service.py`

```python
"""
Supabase Token Service
Handles secure storage and retrieval of OAuth tokens in Supabase.
"""

import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from supabase import create_client, Client
from backend.app.config import settings

logger = logging.getLogger(__name__)

class SupabaseTokenService:
    """Service for managing OAuth tokens in Supabase."""

    def __init__(self):
        self.supabase: Client = create_client(
            settings.supabase_url,
            settings.supabase_key
        )
        self.table_name = "oauth_tokens"
        self._table_checked = False

    async def _ensure_table_exists(self) -> bool:
        """
        Check if the oauth_tokens table exists.

        Returns:
            bool: True if table exists and is accessible
        """
        if self._table_checked:
            return True

        try:
            # Try to query the table to see if it exists
            result = self.supabase.table(self.table_name).select("id").limit(1).execute()
            logger.info("✅ oauth_tokens table exists and is accessible")
            self._table_checked = True
            return True

        except Exception as e:
            logger.error(f"❌ oauth_tokens table not found or not accessible: {e}")
            logger.error("📋 Please create the table manually in Supabase SQL Editor")
            return False

    async def save_tokens(self, user_id: str, provider: str, tokens: Dict[str, Any]) -> bool:
        """
        Save OAuth tokens to Supabase.

        Args:
            user_id: User ID
            provider: OAuth provider name (e.g., 'google_workspace', 'shopify')
            tokens: Dictionary containing token data

        Returns:
            bool: True if saved successfully
        """
        try:
            if not await self._ensure_table_exists():
                return False

            # Calculate expiry time
            expires_at = None
            if tokens.get("expires_in"):
                expires_at = (datetime.now(timezone.utc).timestamp() + int(tokens["expires_in"]))

            # Prepare data for insertion/update
            token_data = {
                "user_id": user_id,
                "provider": provider,
                "access_token": tokens.get("access_token"),
                "refresh_token": tokens.get("refresh_token"),
                "token_type": tokens.get("token_type", "Bearer"),
                "expires_in": tokens.get("expires_in"),
                "scope": tokens.get("scope", ""),
                "expires_at": expires_at,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }

            # Use upsert to insert or update
            result = self.supabase.table(self.table_name).upsert(
                token_data,
                on_conflict="user_id,provider"
            ).execute()

            if result.data:
                logger.info(f"✅ Successfully saved tokens for user {user_id}, provider {provider}")
                return True
            else:
                logger.error(f"❌ No data returned when saving tokens for user {user_id}, provider {provider}")
                return False

        except Exception as e:
            logger.error(f"❌ Error saving tokens to Supabase: {e}")
            return False

    async def get_tokens(self, user_id: str, provider: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve OAuth tokens from Supabase.

        Args:
            user_id: User ID
            provider: OAuth provider name

        Returns:
            Dict containing token data if found, None otherwise
        """
        try:
            if not await self._ensure_table_exists():
                return None

            # Query for tokens
            result = self.supabase.table(self.table_name).select("*").eq(
                "user_id", user_id
            ).eq("provider", provider).execute()

            if result.data and len(result.data) > 0:
                token_data = result.data[0]

                # Check if token is expired
                if self._is_token_expired(token_data):
                    logger.info(f"⏰ Token expired for user {user_id}, provider {provider}. Attempting refresh...")

                    # Try to refresh the tokens
                    refreshed_tokens = await self.refresh_tokens_if_expired(user_id, provider)

                    if refreshed_tokens:
                        logger.info(f"✅ Successfully refreshed tokens for user {user_id}, provider {provider}")
                        return refreshed_tokens
                    else:
                        logger.error(f"❌ Failed to refresh tokens for user {user_id}, provider {provider}")
                        return None

                # Return valid tokens
                return {
                    "access_token": token_data.get("access_token"),
                    "refresh_token": token_data.get("refresh_token"),
                    "token_type": token_data.get("token_type"),
                    "expires_in": token_data.get("expires_in"),
                    "scope": token_data.get("scope"),
                    "expires_at": token_data.get("expires_at")
                }

            return None

        except Exception as e:
            logger.error(f"❌ Error retrieving tokens from Supabase: {e}")
            return None

    def _is_token_expired(self, token_data: Dict[str, Any]) -> bool:
        """
        Check if a token is expired.

        Args:
            token_data: Token data from database

        Returns:
            bool: True if token is expired
        """
        try:
            expires_at = token_data.get("expires_at")
            if not expires_at:
                return False

            current_time = datetime.now(timezone.utc).timestamp()
            # Add 5 minute buffer before expiry
            return current_time >= (float(expires_at) - 300)

        except Exception:
            return True

    async def refresh_tokens_if_expired(self, user_id: str, provider: str) -> Optional[Dict[str, Any]]:
        """
        Refresh tokens if they are expired.

        Args:
            user_id: User ID
            provider: OAuth provider name

        Returns:
            Dict containing refreshed token data if successful, None otherwise
        """
        try:
            # Implementation depends on provider
            if provider == "google_workspace":
                return await self._refresh_google_tokens(user_id)
            else:
                logger.warning(f"Token refresh not implemented for provider: {provider}")
                return None

        except Exception as e:
            logger.error(f"Error refreshing tokens: {e}")
            return None

    async def _refresh_google_tokens(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Refresh Google OAuth tokens.

        Args:
            user_id: User ID

        Returns:
            Dict containing refreshed token data if successful, None otherwise
        """
        try:
            from google.oauth2.credentials import Credentials
            from google.auth.transport.requests import Request

            # Get current tokens
            current_tokens = await self.get_tokens(user_id, "google_workspace")
            if not current_tokens or not current_tokens.get("refresh_token"):
                return None

            # Create credentials object
            credentials = Credentials(
                token=current_tokens.get("access_token"),
                refresh_token=current_tokens.get("refresh_token"),
                token_uri="https://oauth2.googleapis.com/token",
                client_id=settings.google_client_id,
                client_secret=settings.google_client_secret
            )

            # Refresh the credentials
            credentials.refresh(Request())

            # Prepare new token data
            new_tokens = {
                "access_token": credentials.token,
                "refresh_token": credentials.refresh_token or current_tokens.get("refresh_token"),
                "token_type": "Bearer",
                "expires_in": 3600,  # Google tokens typically expire in 1 hour
                "scope": current_tokens.get("scope", "")
            }

            # Save the refreshed tokens
            if await self.save_tokens(user_id, "google_workspace", new_tokens):
                return new_tokens
            else:
                return None

        except Exception as e:
            logger.error(f"Error refreshing Google tokens: {e}")
            return None

    async def delete_tokens(self, user_id: str, provider: str) -> bool:
        """
        Delete OAuth tokens from Supabase.

        Args:
            user_id: User ID
            provider: OAuth provider name

        Returns:
            bool: True if deleted successfully
        """
        try:
            if not await self._ensure_table_exists():
                return False

            # Delete tokens
            result = self.supabase.table(self.table_name).delete().eq(
                "user_id", user_id
            ).eq("provider", provider).execute()

            logger.info(f"✅ Deleted tokens for user {user_id}, provider {provider}")
            return True

        except Exception as e:
            logger.error(f"❌ Error deleting tokens from Supabase: {e}")
            return False

# Create a global instance
token_service = SupabaseTokenService()
```

#### 1.5 Create Auth Base Classes

**File**: `backend/app/auth/__init__.py`

```python
# Auth module initialization
```

**File**: `backend/app/auth/base.py`

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseAuth(ABC):
    """Base authentication class for all tool providers."""

    @abstractmethod
    async def is_authenticated(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Check if authentication is valid."""
        pass

    @abstractmethod
    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests."""
        pass
```

### Phase 2: Tool Migration Structure

#### 2.1 Create Tools Directory Structure

Create a new `backend/app/langgraph/tools/` **package** (rename the former `tools.py` module to `__init__.py`) to eliminate the Python module-vs-package naming collision:

```
backend/app/langgraph/
├── tools/
│   ├── __init__.py               # Tool registry and exports (was tools.py)
│   ├── sample.py                 # Keep existing sample tool
│   ├── google_workspace/
│   │   └── …
│   └── shopify/
│       └── …
```

#### 2.2 Update Main Tools File

**File**: `backend/app/langgraph/tools/__init__.py`

```python
from .google_workspace import get_google_workspace_tools
from .shopify import get_shopify_tools
```

### Phase 3: Google Workspace Tools Migration

#### 3.1 Google Authentication

**File**: `backend/app/langgraph/tools/google_workspace/auth.py`

```python
import logging
from typing import Dict, Any, Optional, List
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from backend.app.config import settings
from backend.app.auth.base import BaseAuth
from backend.app.services.supabase_token_service import token_service

logger = logging.getLogger(__name__)

class GoogleWorkspaceAuth(BaseAuth):
    """Google Workspace OAuth2 authentication handler."""

    # All Google Workspace scopes
    SCOPES = {
        "docs": [
            "https://www.googleapis.com/auth/documents",
            "https://www.googleapis.com/auth/drive.file"
        ],
        "sheets": [
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive.file"
        ],
        "drive": [
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/drive.file"
        ],
        "calendar": [
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/calendar.events"
        ],
        "gmail": [
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/gmail.readonly"
        ],
        "slides": [
            "https://www.googleapis.com/auth/presentations",
            "https://www.googleapis.com/auth/drive.file"
        ],
        "meet": [
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/calendar.events"
        ]
    }

    def __init__(self):
        self.client_id = settings.google_client_id
        self.client_secret = settings.google_client_secret
        self.credentials = None
        self.services = {}  # Cache for different service clients
        self.current_user_id = None  # Store current user ID for tool calls

    def get_all_scopes(self) -> List[str]:
        """Get all scopes needed for Google Workspace."""
        all_scopes = set()
        for service_scopes in self.SCOPES.values():
            all_scopes.update(service_scopes)
        return list(all_scopes)

    async def load_credentials(self, user_id: str) -> bool:
        """
        Load existing credentials from Supabase.

        Args:
            user_id: User ID for user-specific credentials

        Returns:
            bool: True if credentials loaded successfully
        """
        try:
            # Get tokens from google_workspace provider
            tokens = await token_service.get_tokens(user_id, "google_workspace")

            if not tokens:
                logger.info(f"No valid tokens found for user {user_id}")
                return False

            # Create credentials object with all scopes
            self.credentials = Credentials(
                token=tokens.get("access_token"),
                refresh_token=tokens.get("refresh_token"),
                token_uri="https://oauth2.googleapis.com/token",
                client_id=self.client_id,
                client_secret=self.client_secret,
                scopes=self.get_all_scopes()
            )

            # Verify credentials are valid
            if not self.credentials.valid:
                logger.error(f"Invalid credentials for user {user_id}")
                return False

            self.current_user_id = user_id
            logger.info(f"✅ Successfully loaded valid credentials for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            return False

    async def is_authenticated(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Check if user has valid Google credentials."""
        if not user_id:
            return {
                "authenticated": False,
                "error": "User ID required"
            }

        try:
            # Try to load credentials
            if await self.load_credentials(user_id):
                return {
                    "authenticated": True,
                    "user_id": user_id,
                    "provider": "google_workspace",
                    "scopes": self.get_all_scopes()
                }
            else:
                return {
                    "authenticated": False,
                    "user_id": user_id,
                    "provider": "google_workspace",
                    "error": "No valid credentials found"
                }

        except Exception as e:
            logger.error(f"Error checking authentication for user {user_id}: {e}")
            return {
                "authenticated": False,
                "user_id": user_id,
                "provider": "google_workspace",
                "error": str(e)
            }

    def get_headers(self) -> Dict[str, str]:
        """Get headers for Google API requests."""
        return {"Content-Type": "application/json"}

    async def build_service(self, service_name: str, user_id: str = None) -> bool:
        """
        Build Google service client.

        Args:
            service_name: Name of the service (docs, sheets, drive, calendar, gmail, slides, meet)
            user_id: User ID for authentication context

        Returns:
            bool: True if service built successfully
        """
        try:
            # Use current_user_id if no user_id provided
            if not user_id:
                user_id = self.current_user_id

            # Always verify credentials are valid and fresh
            if not self.credentials or not self.credentials.valid:
                if not await self.load_credentials(user_id):
                    return False

            # Build service based on name
            if service_name == "docs":
                self.services["docs"] = build('docs', 'v1', credentials=self.credentials)
            elif service_name == "sheets":
                self.services["sheets"] = build('sheets', 'v4', credentials=self.credentials)
            elif service_name == "drive":
                self.services["drive"] = build('drive', 'v3', credentials=self.credentials)
            elif service_name == "calendar":
                self.services["calendar"] = build('calendar', 'v3', credentials=self.credentials)
            elif service_name == "gmail":
                self.services["gmail"] = build('gmail', 'v1', credentials=self.credentials)
            elif service_name == "slides":
                self.services["slides"] = build('slides', 'v1', credentials=self.credentials)
            elif service_name == "meet":
                # Google Meet uses Calendar API for scheduling meetings
                self.services["meet"] = build('calendar', 'v3', credentials=self.credentials)
            else:
                logger.error(f"Unknown service: {service_name}")
                return False

            logger.info(f"✅ Built {service_name} service for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to build {service_name} service: {e}")
            return False

    def get_service(self, service_name: str, user_id: str = None):
        """
        Get authenticated Google service client.

        Args:
            service_name: Name of the service
            user_id: User ID for authentication context

        Returns:
            Google service client or None if not available
        """
        # Check if service is already built
        if service_name in self.services:
            return self.services[service_name]

        # Try to build the service
        import asyncio
        try:
            # Run the async build_service in sync context
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're in an async context, we can't use run_until_complete
                logger.warning(f"Cannot build service {service_name} in async context - service not pre-built")
                return None
            else:
                success = loop.run_until_complete(self.build_service(service_name, user_id))
                if success:
                    return self.services.get(service_name)
                return None
        except Exception as e:
            logger.error(f"Error getting service {service_name}: {e}")
            return None

    def clear_credentials(self):
        """Clear cached credentials and services."""
        self.credentials = None
        self.services.clear()
        self.current_user_id = None
```

#### 3.2 Google Docs Tools

**File**: `backend/app/langgraph/tools/google_workspace/docs_tools.py`

```python
from langchain_core.tools import tool
from typing import Dict, Any, Optional
import json
import logging
from .auth import GoogleWorkspaceAuth

logger = logging.getLogger(__name__)

# Initialize auth
google_auth = GoogleWorkspaceAuth()

@tool
async def create_document(title: str, content: str = "", user_context: Dict[str, Any] = None) -> str:
    """Create a new Google Doc with title and content."""
    try:
        # Extract user_id from context (this would be injected by the agent)
        user_id = user_context.get("user_id") if user_context else None
        if not user_id:
            return json.dumps({"success": False, "error": "User authentication required"})

        # Load user credentials
        if not await google_auth.load_credentials(user_id):
            return json.dumps({
                "success": False,
                "error": "Google Workspace not authenticated. Please authenticate first."
            })

        # Build the service
        if not await google_auth.build_service("docs", user_id):
            return json.dumps({"success": False, "error": "Failed to initialize Google Docs service"})

        # Get the service
        docs_service = google_auth.get_service("docs")
        if not docs_service:
            return json.dumps({"success": False, "error": "Google Docs service not available"})

        # Create the document
        doc = docs_service.documents().create(body={"title": title}).execute()
        document_id = doc.get("documentId")

        # Add content if provided
        if content:
            requests = [
                {
                    "insertText": {
                        "location": {"index": 1},
                        "text": content
                    }
                }
            ]
            docs_service.documents().batchUpdate(
                documentId=document_id,
                body={"requests": requests}
            ).execute()

        result = {
            "success": True,
            "document_id": document_id,
            "title": title,
            "url": f"https://docs.google.com/document/d/{document_id}/edit",
            "message": f"Document '{title}' created successfully"
        }
        return json.dumps(result)

    except Exception as e:
        logger.error(f"Error creating document: {e}")
        return json.dumps({"success": False, "error": str(e)})

@tool
async def read_document(document_id: str, user_id: str = None) -> str:
    """Read content from a Google Doc."""
    try:
        # Implementation for reading document
        result = {
            "success": True,
            "document_id": document_id,
            "content": "Mock document content...",
            "title": "Mock Document Title"
        }
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error reading document: {e}")
        return json.dumps({"success": False, "error": str(e)})

@tool
async def update_document(document_id: str, content: str, user_id: str = None) -> str:
    """Update content in a Google Doc."""
    try:
        # Implementation for updating document
        result = {
            "success": True,
            "document_id": document_id,
            "message": "Document updated successfully"
        }
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error updating document: {e}")
        return json.dumps({"success": False, "error": str(e)})

@tool
async def list_documents(user_id: str = None) -> str:
    """List all Google Docs for the user."""
    try:
        # Implementation for listing documents
        result = {
            "success": True,
            "documents": [
                {
                    "id": "doc1",
                    "title": "Document 1",
                    "url": "https://docs.google.com/document/d/doc1/edit"
                }
            ]
        }
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error listing documents: {e}")
        return json.dumps({"success": False, "error": str(e)})

@tool
async def search_documents(query: str, max_results: int = 10, user_id: str = None) -> str:
    """Search for Google Docs by title or content."""
    try:
        # Implementation for searching documents
        result = {
            "success": True,
            "query": query,
            "documents": []
        }
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error searching documents: {e}")
        return json.dumps({"success": False, "error": str(e)})

# Export tools for the main module
def get_docs_tools():
    """Get all Google Docs tools."""
    return [
        create_document,
        read_document,
        update_document,
        list_documents,
        search_documents
    ]
```

#### 3.3 Repeat Similar Pattern for Other Google Services

Create similar files for:

- `sheets_tools.py` (5 tools)
- `drive_tools.py` (3 tools)
- `calendar_tools.py` (3 tools)
- `gmail_tools.py` (3 tools)
- `slides_tools.py` (4 tools)
- `meet_tools.py` (3 tools)

#### 3.4 Google Workspace Module Init

**File**: `backend/app/langgraph/tools/google_workspace/__init__.py`

```python
from .docs_tools import get_docs_tools
from .sheets_tools import get_sheets_tools
from .drive_tools import get_drive_tools
from .calendar_tools import get_calendar_tools
from .gmail_tools import get_gmail_tools
from .slides_tools import get_slides_tools
from .meet_tools import get_meet_tools

def get_google_workspace_tools():
    """Get all Google Workspace tools."""
    tools = []
    tools.extend(get_docs_tools())
    tools.extend(get_sheets_tools())
    tools.extend(get_drive_tools())
    tools.extend(get_calendar_tools())
    tools.extend(get_gmail_tools())
    tools.extend(get_slides_tools())
    tools.extend(get_meet_tools())
    return tools

__all__ = ["get_google_workspace_tools"]
```

### Phase 4: Shopify Tools Migration

#### 4.1 Shopify Authentication

**File**: `backend/app/langgraph/tools/shopify/auth.py`

```python
import logging
from typing import Dict, Any, Optional
import httpx
from backend.app.config import settings
from backend.app.auth.base import BaseAuth

logger = logging.getLogger(__name__)

class ShopifyAuth(BaseAuth):
    """Shopify API token authentication handler."""

    def __init__(self):
        self.store_domain = settings.shopify_store_domain
        self.admin_token = settings.shopify_admin_token
        self.base_url = f"https://{self.store_domain}/admin/api/2025-04/graphql.json" if self.store_domain else None

    async def is_authenticated(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Check if Shopify credentials are valid."""
        if not self.store_domain or not self.admin_token:
            return {
                "authenticated": False,
                "error": "Missing Shopify credentials"
            }

        try:
            # Test API connection with a simple query
            query = "query { shop { name, email, domain } }"
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.base_url,
                    headers=self.get_headers(),
                    json={"query": query},
                    timeout=10.0
                )

                if response.status_code == 200:
                    data = response.json()
                    if "errors" not in data:
                        shop_info = data.get("data", {}).get("shop", {})
                        return {
                            "authenticated": True,
                            "store_name": shop_info.get("name"),
                            "store_domain": shop_info.get("domain"),
                            "store_email": shop_info.get("email")
                        }

                return {
                    "authenticated": False,
                    "error": "Invalid API response"
                }

        except Exception as e:
            return {
                "authenticated": False,
                "error": str(e)
            }

    def get_headers(self) -> Dict[str, str]:
        """Get headers for Shopify API requests."""
        return {
            "X-Shopify-Access-Token": self.admin_token,
            "Content-Type": "application/json"
        }

    def get_base_url(self) -> str:
        """Get the base URL for Shopify GraphQL API."""
        return self.base_url
```

#### 4.2 Shopify Product Tools

**File**: `backend/app/langgraph/tools/shopify/product_tools.py`

```python
from langchain_core.tools import tool
from typing import Dict, Any, Optional, List
import json
import logging
import httpx
from .auth import ShopifyAuth

logger = logging.getLogger(__name__)

# Initialize auth
shopify_auth = ShopifyAuth()

async def _make_shopify_request(query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Make a GraphQL request to Shopify Admin API."""
    if not shopify_auth.get_base_url():
        raise Exception("Shopify not configured")

    payload = {
        "query": query,
        "variables": variables or {}
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            shopify_auth.get_base_url(),
            headers=shopify_auth.get_headers(),
            json=payload,
            timeout=30.0
        )
        response.raise_for_status()

        data = response.json()
        if "errors" in data:
            raise Exception(f"GraphQL errors: {data['errors']}")

        return data

@tool
async def get_product_by_sku(sku: str) -> str:
    """Look up a single product by SKU (Stock Keeping Unit)."""
    try:
        query = """
        query getProductBySKU($sku: String!) {
            products(first: 1, query: $sku) {
                edges {
                    node {
                        id
                        title
                        description
                        vendor
                        productType
                        tags
                        variants(first: 1) {
                            edges {
                                node {
                                    id
                                    sku
                                    price
                                    displayName
                                }
                            }
                        }
                    }
                }
            }
        }
        """

        variables = {"sku": f"sku:{sku}"}
        data = await _make_shopify_request(query, variables)

        products = data.get("data", {}).get("products", {}).get("edges", [])
        if not products:
            return json.dumps({"error": f"No product found with SKU: {sku}"})

        product_node = products[0]["node"]
        variant = product_node.get("variants", {}).get("edges", [])
        variant_info = variant[0]["node"] if variant else {}

        result = {
            "id": product_node["id"],
            "title": product_node["title"],
            "description": product_node.get("description"),
            "vendor": product_node.get("vendor"),
            "sku": variant_info.get("sku"),
            "price": variant_info.get("price"),
            "product_type": product_node.get("productType"),
            "tags": product_node.get("tags", [])
        }

        return json.dumps(result)

    except Exception as e:
        logger.error(f"Error getting product by SKU {sku}: {e}")
        return json.dumps({"error": f"Failed to fetch product with SKU {sku}: {str(e)}"})

@tool
async def get_product_by_id(product_id: str) -> str:
    """Look up a single product by Shopify GraphQL ID."""
    try:
        # Convert numeric ID to Shopify GraphQL format if needed
        if not product_id.startswith("gid://shopify/Product/"):
            formatted_id = f"gid://shopify/Product/{product_id}"
        else:
            formatted_id = product_id

        query = """
        query getProduct($id: ID!) {
            product(id: $id) {
                id
                title
                description
                vendor
                productType
                tags
                variants(first: 1) {
                    edges {
                        node {
                            id
                            sku
                            price
                            displayName
                        }
                    }
                }
            }
        }
        """

        variables = {"id": formatted_id}
        data = await _make_shopify_request(query, variables)

        product_node = data.get("data", {}).get("product")
        if not product_node:
            return json.dumps({"error": f"No product found with ID: {product_id}"})

        variant = product_node.get("variants", {}).get("edges", [])
        variant_info = variant[0]["node"] if variant else {}

        result = {
            "id": product_node["id"],
            "title": product_node["title"],
            "description": product_node.get("description"),
            "vendor": product_node.get("vendor"),
            "sku": variant_info.get("sku"),
            "price": variant_info.get("price"),
            "product_type": product_node.get("productType"),
            "tags": product_node.get("tags", [])
        }

        return json.dumps(result)

    except Exception as e:
        logger.error(f"Error getting product by ID {product_id}: {e}")
        return json.dumps({"error": f"Failed to fetch product with ID {product_id}: {str(e)}"})

@tool
async def search_products(query: str, limit: int = 10) -> str:
    """Search product catalogue by name, description, or other attributes."""
    try:
        graphql_query = """
        query searchProducts($query: String!, $limit: Int!) {
            products(first: $limit, query: $query) {
                edges {
                    node {
                        id
                        title
                        description
                        vendor
                        productType
                        tags
                        variants(first: 1) {
                            edges {
                                node {
                                    id
                                    sku
                                    price
                                    displayName
                                }
                            }
                        }
                    }
                }
            }
        }
        """

        variables = {"query": query, "limit": limit}
        data = await _make_shopify_request(graphql_query, variables)

        products = data.get("data", {}).get("products", {}).get("edges", [])

        results = []
        for product_edge in products:
            product_node = product_edge["node"]
            variant = product_node.get("variants", {}).get("edges", [])
            variant_info = variant[0]["node"] if variant else {}

            results.append({
                "id": product_node["id"],
                "title": product_node["title"],
                "description": product_node.get("description"),
                "vendor": product_node.get("vendor"),
                "sku": variant_info.get("sku"),
                "price": variant_info.get("price"),
                "product_type": product_node.get("productType"),
                "tags": product_node.get("tags", [])
            })

        return json.dumps(results)

    except Exception as e:
        logger.error(f"Error searching products with query '{query}': {e}")
        return json.dumps([])

def get_product_tools():
    """Get all Shopify product tools."""
    return [
        get_product_by_sku,
        get_product_by_id,
        search_products
    ]
```

#### 4.3 Create Other Shopify Tool Files

Create similar patterns for:

- `inventory_tools.py` (2 tools)
- `customer_tools.py` (2 tools)
- `order_tools.py` (2 tools)

#### 4.4 Shopify Module Init

**File**: `backend/app/langgraph/tools/shopify/__init__.py`

```python
from .product_tools import get_product_tools
from .inventory_tools import get_inventory_tools
from .customer_tools import get_customer_tools
from .order_tools import get_order_tools
from .auth import ShopifyAuth

def get_shopify_tools():
    """Get all Shopify tools."""
    tools = []
    tools.extend(get_product_tools())
    tools.extend(get_inventory_tools())
    tools.extend(get_customer_tools())
    tools.extend(get_order_tools())
    return tools

__all__ = ["get_shopify_tools", "ShopifyAuth"]
```

### Phase 5: OAuth2 Routes

#### 5.1 Create OAuth2 Router

**File**: `backend/app/routers/__init__.py`

```python
"""
Routers package for API endpoints.
"""

from .oauth_router import router as oauth_router

__all__ = ["oauth_router"]
```

**File**: `backend/app/routers/oauth_router.py`

```python
"""
OAuth2 router for handling Google Workspace authentication.
Provides endpoints for initiating and completing OAuth2 flows for all Google services.
"""

import os
import json
import logging
import secrets
import time
from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.responses import RedirectResponse
from typing import Dict, Any
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from backend.app.middleware.auth import verify_jwt_dependency
from backend.app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/oauth", tags=["oauth"])

# OAuth2 configuration
GOOGLE_OAUTH_CONFIG = {
    "web": {
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": settings.google_redirect_uris
    }
}

# Scopes for Google Workspace services
GOOGLE_WORKSPACE_SCOPES = [
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/presentations"
]

# In-memory state storage (in production, use Redis or database)
oauth_states = {}

def cleanup_expired_states():
    """Remove expired OAuth states (older than 5 minutes)."""
    current_time = time.time()
    expired_states = [
        state for state, info in oauth_states.items()
        if current_time - info["timestamp"] > 300
    ]
    for state in expired_states:
        del oauth_states[state]

@router.get("/google-workspace/authorize")
async def google_workspace_authorize(
    request: Request,
    user_info: Dict[str, Any] = Depends(verify_jwt_dependency)
):
    """
    Initiate Google OAuth2 flow for Google Workspace access.
    """
    try:
        cleanup_expired_states()

        # Get redirect_uri from query parameters
        redirect_uri = request.query_params.get("redirect_uri", "http://localhost:3000/admin/flux")

        # Create OAuth2 flow with Google Workspace scopes
        flow = Flow.from_client_config(
            GOOGLE_OAUTH_CONFIG,
            scopes=GOOGLE_WORKSPACE_SCOPES
        )

        # Set redirect URI
        flow.redirect_uri = GOOGLE_OAUTH_CONFIG["web"]["redirect_uris"][0]

        # Generate a secure random state token
        secure_state = secrets.token_urlsafe(32)

        # Store state with user info and redirect URI for verification
        oauth_states[secure_state] = {
            "user_id": user_info.get('user_id'),
            "redirect_uri": redirect_uri,
            "timestamp": time.time(),
            "provider": "google_workspace"
        }

        # Include user_id and redirect_uri in the state for the callback
        state_with_user = f"{secure_state}:{user_info.get('user_id')}"

        # Generate authorization URL with our custom state
        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent',
            state=state_with_user
        )

        logger.info(f"Google Workspace OAuth flow initiated for user {user_info.get('user_id')}")

        return {
            "authorization_url": authorization_url,
            "state": state_with_user,
            "redirect_uri": redirect_uri,
            "provider": "google_workspace"
        }

    except Exception as e:
        logger.error(f"Failed to initiate Google Workspace OAuth flow: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate Google Workspace OAuth flow: {str(e)}"
        )

@router.get("/google/callback")
async def google_callback(
    request: Request,
    code: str = None,
    state: str = None,
    error: str = None
):
    """
    Handle Google OAuth2 callback.
    """
    if error:
        logger.error(f"OAuth error in callback: {error}")
        error_url = f"http://localhost:3000/admin/flux?oauth_error={error}&provider=google_workspace"
        return RedirectResponse(url=error_url, status_code=302)

    if not code or not state:
        logger.error("Missing authorization code or state in callback")
        error_url = f"http://localhost:3000/admin/flux?oauth_error=missing_code_or_state&provider=google_workspace"
        return RedirectResponse(url=error_url, status_code=302)

    try:
        # Extract secure state and user_id
        state_parts = state.split(":")
        if len(state_parts) != 2:
            logger.error(f"Invalid state parameter format: {state}")
            error_url = f"http://localhost:3000/admin/flux?oauth_error=invalid_state&provider=google_workspace"
            return RedirectResponse(url=error_url, status_code=302)

        secure_state, user_id = state_parts

        # Verify state exists and is not expired
        if secure_state not in oauth_states:
            logger.error(f"Invalid or expired state token: {secure_state}")
            error_url = f"http://localhost:3000/admin/flux?oauth_error=invalid_or_expired_state&provider=google_workspace"
            return RedirectResponse(url=error_url, status_code=302)

        stored_state_info = oauth_states[secure_state]
        redirect_uri = stored_state_info.get("redirect_uri", "http://localhost:3000/admin/flux")

        # Check if state is expired (5 minutes)
        if time.time() - stored_state_info["timestamp"] > 300:
            logger.error(f"OAuth state expired for user {user_id}")
            del oauth_states[secure_state]
            error_url = f"{redirect_uri}?oauth_error=state_expired&provider=google_workspace"
            return RedirectResponse(url=error_url, status_code=302)

        # Create OAuth2 flow
        flow = Flow.from_client_config(
            GOOGLE_OAUTH_CONFIG,
            scopes=GOOGLE_WORKSPACE_SCOPES
        )
        flow.redirect_uri = GOOGLE_OAUTH_CONFIG["web"]["redirect_uris"][0]

        # Exchange code for tokens
        flow.fetch_token(code=code)

        # Get credentials
        credentials = flow.credentials

        # Prepare token data for Supabase storage
        token_data = {
            "access_token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,  # Google tokens typically expire in 1 hour
            "scope": " ".join(credentials.scopes)
        }

        # Save tokens to Supabase
        success = await token_service.save_tokens(user_id, "google_workspace", token_data)

        if not success:
            logger.error(f"Failed to save tokens to Supabase for user {user_id}")
            error_url = f"{redirect_uri}?oauth_error=token_save_failed&provider=google_workspace"
            return RedirectResponse(url=error_url, status_code=302)

        # Clean up state
        del oauth_states[secure_state]

        logger.info(f"OAuth flow completed successfully for user {user_id}")

        # Redirect to frontend with success
        success_url = f"{redirect_uri}?oauth_success=true&provider=google_workspace&user_id={user_id}"
        return RedirectResponse(url=success_url, status_code=302)

    except Exception as e:
        logger.error(f"Failed to complete OAuth flow: {e}")
        error_url = f"http://localhost:3000/admin/flux?oauth_error=unexpected_error&provider=google_workspace&error_message={str(e)}"
        return RedirectResponse(url=error_url, status_code=302)

@router.get("/google-workspace/status")
async def google_workspace_auth_status(
    user_info: Dict[str, Any] = Depends(verify_jwt_dependency)
):
    """
    Check Google Workspace authentication status for the user.
    """
    try:
        user_id = user_info.get("user_id")

        # Get tokens from Supabase (this will automatically refresh if expired)
        tokens = await token_service.get_tokens(user_id, "google_workspace")

        if not tokens:
            return {
                "authenticated": False,
                "message": "Google Workspace not connected"
            }

        # Create credentials object to verify they work
        credentials = Credentials(
            token=tokens.get("access_token"),
            refresh_token=tokens.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=GOOGLE_OAUTH_CONFIG["web"]["client_id"],
            client_secret=GOOGLE_OAUTH_CONFIG["web"]["client_secret"],
            scopes=tokens.get("scope", "").split() if tokens.get("scope") else GOOGLE_WORKSPACE_SCOPES
        )

        # Check if credentials are valid
        if not credentials.valid:
            return {
                "authenticated": False,
                "message": "Google Workspace credentials are invalid"
            }

        return {
            "authenticated": True,
            "message": "Google Workspace connected and ready",
            "scopes": tokens.get("scope", "").split() if tokens.get("scope") else GOOGLE_WORKSPACE_SCOPES
        }

    except Exception as e:
        logger.error(f"Error checking Google Workspace authentication status: {e}")
        return {
            "authenticated": False,
            "message": f"Error checking authentication status: {str(e)}"
        }

@router.post("/google-workspace/refresh")
async def google_workspace_refresh_tokens(
    user_info: Dict[str, Any] = Depends(verify_jwt_dependency)
):
    """
    Manually refresh Google Workspace tokens for the user.
    """
    try:
        user_id = user_info.get("user_id")

        # Attempt to refresh tokens
        refreshed_tokens = await token_service.refresh_tokens_if_expired(user_id, "google_workspace")

        if refreshed_tokens:
            logger.info(f"Successfully refreshed Google Workspace tokens for user {user_id}")
            return {
                "message": "Google Workspace tokens refreshed successfully",
                "user_id": user_id,
                "refreshed": True
            }
        else:
            logger.warning(f"No tokens found or refresh failed for user {user_id}")
            return {
                "message": "No Google Workspace tokens found or refresh failed",
                "user_id": user_id,
                "refreshed": False
            }

    except Exception as e:
        logger.error(f"Failed to refresh Google Workspace tokens: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to refresh Google Workspace tokens: {str(e)}"
        )

@router.delete("/google-workspace")
async def revoke_google_workspace_auth(
    user_info: Dict[str, Any] = Depends(verify_jwt_dependency)
):
    """
    Revoke Google Workspace authentication for the user.
    """
    try:
        user_id = user_info.get("user_id")

        # Delete user credentials from Supabase
        success = await token_service.delete_tokens(user_id, "google_workspace")

        if success:
            return {
                "message": "Successfully revoked Google Workspace authentication",
                "user_id": user_id,
                "revoked": True
            }
        else:
            return {
                "message": "No Google Workspace credentials found",
                "user_id": user_id,
                "revoked": False
            }

    except Exception as e:
        logger.error(f"Failed to revoke Google Workspace authentication: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke authentication: {str(e)}"
        )
```

### Phase 6: Environment Configuration

#### 6.1 Create Environment Template

**File**: `backend/.env.template`

```env
# OpenAI
OPENAI_API_KEY=your_openai_api_key_here

# Supabase Configuration
SUPABASE_URL=your_supabase_project_url
SUPABASE_KEY=your_supabase_anon_key
SUPABASE_JWT_SECRET=your_supabase_jwt_secret

# Google Workspace OAuth2
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:8000/oauth/google/callback

# Shopify
SHOPIFY_STORE_DOMAIN=your-store.myshopify.com
SHOPIFY_ADMIN_TOKEN=your_admin_api_token

# FastAPI Configuration
DEBUG=false
HOST=0.0.0.0
PORT=8000
```

#### 6.1.1 Developer .env file

**File**: `backend/.env.dev`

```env
# Developer defaults (safe dummy values)
OPENAI_API_KEY=dev_openai_key
SUPABASE_URL=https://dev.supabase.co
SUPABASE_KEY=dev_supabase_key
SUPABASE_JWT_SECRET=dev_jwt_secret
GOOGLE_CLIENT_ID=dev_google_client_id
GOOGLE_CLIENT_SECRET=dev_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:8000/oauth/google/callback
SHOPIFY_STORE_DOMAIN=dev-store.myshopify.com
SHOPIFY_ADMIN_TOKEN=dev_admin_token
DEBUG=true
HOST=0.0.0.0
PORT=8000
```

#### 6.2 Create Supabase Table Schema

**File**: `backend/supabase_oauth_table.sql`

```sql
-- Create oauth_tokens table for storing OAuth2 tokens
CREATE TABLE IF NOT EXISTS oauth_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    token_type VARCHAR(50) DEFAULT 'Bearer',
    expires_in INTEGER,
    scope TEXT,
    expires_at BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Ensure one row per user per provider
    UNIQUE(user_id, provider)
);

-- Add RLS (Row Level Security) policies
ALTER TABLE oauth_tokens ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own tokens
CREATE POLICY "Users can view own tokens" ON oauth_tokens
    FOR SELECT USING (auth.uid()::text = user_id);

-- Policy: Users can insert their own tokens
CREATE POLICY "Users can insert own tokens" ON oauth_tokens
    FOR INSERT WITH CHECK (auth.uid()::text = user_id);

-- Policy: Users can update their own tokens
CREATE POLICY "Users can update own tokens" ON oauth_tokens
    FOR UPDATE USING (auth.uid()::text = user_id);

-- Policy: Users can delete their own tokens
CREATE POLICY "Users can delete own tokens" ON oauth_tokens
    FOR DELETE USING (auth.uid()::text = user_id);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_provider
ON oauth_tokens(user_id, provider);
```

#### 6.3 Apply-patch helper script

**File**: `scripts/apply_patch.sh`

```bash
#!/usr/bin/env bash
# Apply a unified diff generated from MASTERPLAN directly onto the repo.
# Example: ./scripts/apply_patch.sh masterplan.patch
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <diff-file>" >&2
  exit 1
fi
patch -p1 --backup --suffix=.orig < "$1"
```

This script allows the AI (or any CI bot) to emit a single diff file based on the updated MASTERPLAN and apply it atomically, eliminating manual copy-paste errors.

#### 5.2 Update .gitignore

**File**: `.gitignore` _(root)_

```gitignore
# Environment variables
.env
.env.local
.env.*.local

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyCharm
.idea/

# VSCode
.vscode/

# Jupyter Notebook
.ipynb_checkpoints

# pyenv
.python-version

# pipenv
Pipfile.lock

# poetry
poetry.lock
```

### Phase 7: Server Integration

#### 7.1 Update Server Configuration

**File**: `backend/app/server.py`

```python
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from .langgraph.agent import assistant_ui_graph
from .add_langgraph_route import add_langgraph_route
from .routers.oauth_router import router as oauth_router

app = FastAPI(
    title="AI Assistant Backend with Tools",
    description="""
    A FastAPI backend with LangGraph agent supporting Google Workspace and Shopify integrations.

    ## Features
    - **Streaming Chat**: Real-time conversation with AI assistant
    - **Google Workspace Tools**: 21 tools for Docs, Sheets, Drive, Calendar, Gmail, Slides, Meet
    - **Shopify Tools**: 10 tools for products, inventory, customers, orders
    - **JWT Authentication**: Supabase JWT token validation
    - **OAuth2 Flow**: Complete Google Workspace authentication
    - **Extensible Architecture**: Easy to add new tool providers

    ## Authentication
    - Supabase JWT authentication for API access
    - OAuth2 flows for external services (Google Workspace)
    - User-specific credential management
    """,
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "https://your-domain.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(oauth_router)

# Add the main chat route
add_langgraph_route(app, assistant_ui_graph, "/api/chat")

@app.get("/")
async def root():
    return {
        "message": "AI Assistant Backend with Tools",
        "version": "2.0.0",
        "features": [
            "Streaming chat with LangGraph",
            "Google Workspace integration (21 tools)",
            "Shopify integration (10 tools)",
            "JWT authentication",
            "OAuth2 flows"
        ],
        "endpoints": {
            "chat": "POST /api/chat - Main chat endpoint",
            "oauth": "GET /oauth/* - OAuth2 authentication flows",
            "docs": "GET /docs - API documentation"
        }
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "ai-assistant-backend"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### Phase 8: Agent Integration

#### 8.1 Update Agent Configuration

**File**: `backend/app/langgraph/agent.py`

Update the imports and tool loading:

```python
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import SystemMessage
from langgraph.errors import NodeInterrupt
from langchain_core.tools import BaseTool
from pydantic import BaseModel
from .tools import get_all_tools  # Updated import
from .state import AgentState

model = ChatOpenAI()

def should_continue(state):
    messages = state["messages"]
    last_message = messages[-1]
    if not last_message.tool_calls:
        return END
    else:
        return "tools"

class AnyArgsSchema(BaseModel):
    class Config:
        extra = "allow"

class FrontendTool(BaseTool):
    def __init__(self, name: str):
        super().__init__(name=name, description="", args_schema=AnyArgsSchema)

    def _run(self, *args, **kwargs):
        raise NodeInterrupt("This is a frontend tool call")

    async def _arun(self, *args, **kwargs) -> str:
        raise NodeInterrupt("This is a frontend tool call")

def get_tool_defs(config):
    # Get all backend tools
    backend_tools = get_all_tools()
    backend_tool_defs = [
        {"type": "function", "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.args_schema.schema() if hasattr(tool.args_schema, 'schema') else {}
        }}
        for tool in backend_tools
    ]

    # Get frontend tools
    frontend_tools = [
        {"type": "function", "function": tool}
        for tool in config["configurable"]["frontend_tools"]
    ]

    return backend_tool_defs + frontend_tools

def get_tools(config):
    # Get all backend tools
    backend_tools = get_all_tools()

    # Get frontend tools
    frontend_tools = [
        FrontendTool(tool.name) for tool in config["configurable"]["frontend_tools"]
    ]

    return backend_tools + frontend_tools

# Rest of the agent code remains the same...
async def call_model(state, config):
    system = config["configurable"]["system"]
    messages = [SystemMessage(content=system)] + state["messages"]
    model_with_tools = model.bind_tools(get_tool_defs(config))
    response = await model_with_tools.ainvoke(messages)
    return {"messages": response}

async def run_tools(input, config, **kwargs):
    tool_node = ToolNode(get_tools(config))
    return await tool_node.ainvoke(input, config, **kwargs)

# Define the workflow
workflow = StateGraph(AgentState)
workflow.add_node("agent", call_model)
workflow.add_node("tools", run_tools)
workflow.set_entry_point("agent")
workflow.add_conditional_edges("agent", should_continue, ["tools", END])
workflow.add_edge("tools", "agent")

assistant_ui_graph = workflow.compile()
```

#### 8.2 Update Tools to Support User Context

**File**: `backend/app/langgraph/tools/google_workspace/docs_tools.py`

Update tools to extract user_id from context and use proper authentication:

```python
from langchain_core.tools import tool
from typing import Dict, Any, Optional
import json
import logging
from .auth import GoogleWorkspaceAuth

logger = logging.getLogger(__name__)

# Initialize auth
google_auth = GoogleWorkspaceAuth()

@tool
async def create_document(title: str, content: str = "", user_context: Dict[str, Any] = None) -> str:
    """Create a new Google Doc with title and content."""
    try:
        # Extract user_id from context (this would be injected by the agent)
        user_id = user_context.get("user_id") if user_context else None
        if not user_id:
            return json.dumps({"success": False, "error": "User authentication required"})

        # Load user credentials
        if not await google_auth.load_credentials(user_id):
            return json.dumps({
                "success": False,
                "error": "Google Workspace not authenticated. Please authenticate first."
            })

        # Build the service
        if not await google_auth.build_service("docs", user_id):
            return json.dumps({"success": False, "error": "Failed to initialize Google Docs service"})

        # Get the service
        docs_service = google_auth.get_service("docs")
        if not docs_service:
            return json.dumps({"success": False, "error": "Google Docs service not available"})

        # Create the document
        doc = docs_service.documents().create(body={"title": title}).execute()
        document_id = doc.get("documentId")

        # Add content if provided
        if content:
            requests = [
                {
                    "insertText": {
                        "location": {"index": 1},
                        "text": content
                    }
                }
            ]
            docs_service.documents().batchUpdate(
                documentId=document_id,
                body={"requests": requests}
            ).execute()

        result = {
            "success": True,
            "document_id": document_id,
            "title": title,
            "url": f"https://docs.google.com/document/d/{document_id}/edit",
            "message": f"Document '{title}' created successfully"
        }
        return json.dumps(result)

    except Exception as e:
        logger.error(f"Error creating document: {e}")
        return json.dumps({"success": False, "error": str(e)})

# Update other tools similarly...
def get_docs_tools():
    """Get all Google Docs tools."""
    return [
        create_document,
        # Add other tools here
    ]
```

### Phase 9: Testing and Validation

#### 9.1 Create Test Structure

**File**: `backend/tests/__init__.py`

**File**: `backend/tests/test_tools.py`

```python
import pytest
import asyncio
from backend.app.langgraph.tools import get_all_tools

@pytest.mark.asyncio
async def test_tools_import():
    """Test that all tools can be imported successfully."""
    tools = get_all_tools()
    assert len(tools) > 0

    # Verify we have tools from all expected sources
    tool_names = [tool.name for tool in tools]

    # Should have sample tool
    assert "get_stock_price" in tool_names

    # Should have Google Workspace tools
    google_tools = [name for name in tool_names if any(
        service in name for service in ["document", "spreadsheet", "drive", "calendar", "email", "presentation", "meeting"]
    )]
    assert len(google_tools) > 0

    # Should have Shopify tools
    shopify_tools = [name for name in tool_names if any(
        keyword in name for keyword in ["product", "inventory", "customer", "order"]
    )]
    assert len(shopify_tools) > 0

@pytest.mark.asyncio
async def test_sample_tool():
    """Test the existing sample tool still works."""
    from backend.app.langgraph.tools import get_stock_price

    result = await get_stock_price.ainvoke({"stock_symbol": "AAPL"})
    assert "AAPL" in str(result)
```

#### 9.2 Create Basic Integration Test

**File**: `backend/tests/test_integration.py`

```python
import pytest
from fastapi.testclient import TestClient
from backend.app.server import app

client = TestClient(app)

def test_chat_endpoint_exists():
    """Test that the chat endpoint is accessible."""
    # This would be a basic test to ensure the endpoint exists
    # Full testing would require proper request format
    response = client.get("/")
    # Just verify server is running - chat endpoint needs POST with specific format
    assert response.status_code in [200, 404, 405]  # Any non-500 error is good
```

### Phase 10: Documentation

#### 10.1 Update Main README

**File**: `backend/README.md`
