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
from app.middleware.auth import verify_jwt_dependency
from app.config import settings
from app.services.supabase_token_service import token_service

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
