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
from app.config import settings

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
