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
        extra = "allow"  # Allow extra fields from environment variables
        env_file_encoding = "utf-8"

settings = Settings()
