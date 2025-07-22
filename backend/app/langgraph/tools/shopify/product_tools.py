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
        query = '''
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
        '''

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

        query = '''
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
        '''

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
        graphql_query = '''
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
        '''

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
