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
