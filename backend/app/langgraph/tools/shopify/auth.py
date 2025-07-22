import logging
from typing import Dict, Any, Optional
import httpx
from app.config import settings
from app.auth.base import BaseAuth

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
