"""
Supabase Token Service
Handles secure storage and retrieval of OAuth tokens in Supabase.
"""

import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from supabase import create_client, Client
from app.config import settings

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
