import logging
from typing import Dict, Any, Optional, List
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from app.config import settings
from app.auth.base import BaseAuth
from app.services.supabase_token_service import token_service

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
