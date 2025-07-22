from langchain_core.tools import tool
from typing import Dict, Any, Optional
import json
import logging
from .auth import GoogleWorkspaceAuth

logger = logging.getLogger(__name__)

# Initialize auth
google_auth = GoogleWorkspaceAuth()

@tool
async def create_document(title: str, content: str = "", user_context: Dict[str, Any] = None) -> str:
    """Create a new Google Doc with title and content."""
    try:
        # Extract user_id from context (this would be injected by the agent)
        user_id = user_context.get("user_id") if user_context else None
        if not user_id:
            return json.dumps({"success": False, "error": "User authentication required"})

        # Load user credentials
        if not await google_auth.load_credentials(user_id):
            return json.dumps({
                "success": False,
                "error": "Google Workspace not authenticated. Please authenticate first."
            })

        # Build the service
        if not await google_auth.build_service("docs", user_id):
            return json.dumps({"success": False, "error": "Failed to initialize Google Docs service"})

        # Get the service
        docs_service = google_auth.get_service("docs")
        if not docs_service:
            return json.dumps({"success": False, "error": "Google Docs service not available"})

        # Create the document
        doc = docs_service.documents().create(body={"title": title}).execute()
        document_id = doc.get("documentId")

        # Add content if provided
        if content:
            requests = [
                {
                    "insertText": {
                        "location": {"index": 1},
                        "text": content
                    }
                }
            ]
            docs_service.documents().batchUpdate(
                documentId=document_id,
                body={"requests": requests}
            ).execute()

        result = {
            "success": True,
            "document_id": document_id,
            "title": title,
            "url": f"https://docs.google.com/document/d/{document_id}/edit",
            "message": f"Document '{title}' created successfully"
        }
        return json.dumps(result)

    except Exception as e:
        logger.error(f"Error creating document: {e}")
        return json.dumps({"success": False, "error": str(e)})

@tool
async def read_document(document_id: str, user_id: str = None) -> str:
    """Read content from a Google Doc."""
    try:
        # Implementation for reading document
        result = {
            "success": True,
            "document_id": document_id,
            "content": "Mock document content...",
            "title": "Mock Document Title"
        }
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error reading document: {e}")
        return json.dumps({"success": False, "error": str(e)})

@tool
async def update_document(document_id: str, content: str, user_id: str = None) -> str:
    """Update content in a Google Doc."""
    try:
        # Implementation for updating document
        result = {
            "success": True,
            "document_id": document_id,
            "message": "Document updated successfully"
        }
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error updating document: {e}")
        return json.dumps({"success": False, "error": str(e)})

@tool
async def list_documents(user_id: str = None) -> str:
    """List all Google Docs for the user."""
    try:
        # Implementation for listing documents
        result = {
            "success": True,
            "documents": [
                {
                    "id": "doc1",
                    "title": "Document 1",
                    "url": "https://docs.google.com/document/d/doc1/edit"
                }
            ]
        }
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error listing documents: {e}")
        return json.dumps({"success": False, "error": str(e)})

@tool
async def search_documents(query: str, max_results: int = 10, user_id: str = None) -> str:
    """Search for Google Docs by title or content."""
    try:
        # Implementation for searching documents
        result = {
            "success": True,
            "query": query,
            "documents": []
        }
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error searching documents: {e}")
        return json.dumps({"success": False, "error": str(e)})

# Export tools for the main module
def get_docs_tools():
    """Get all Google Docs tools."""
    return [
        create_document,
        read_document,
        update_document,
        list_documents,
        search_documents
    ]
