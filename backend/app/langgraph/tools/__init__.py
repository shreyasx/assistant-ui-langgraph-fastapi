from .google_workspace import get_google_workspace_tools
from .shopify import get_shopify_tools
from .sample import search

# Create a tools list that can be imported by agent.py
tools = [search]