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
