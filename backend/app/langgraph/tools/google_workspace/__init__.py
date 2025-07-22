from .docs_tools import get_docs_tools
from .sheets_tools import get_sheets_tools
from .drive_tools import get_drive_tools
from .calendar_tools import get_calendar_tools
from .gmail_tools import get_gmail_tools
from .slides_tools import get_slides_tools
from .meet_tools import get_meet_tools

def get_google_workspace_tools():
    """Get all Google Workspace tools."""
    tools = []
    tools.extend(get_docs_tools())
    tools.extend(get_sheets_tools())
    tools.extend(get_drive_tools())
    tools.extend(get_calendar_tools())
    tools.extend(get_gmail_tools())
    tools.extend(get_slides_tools())
    tools.extend(get_meet_tools())
    return tools

__all__ = ["get_google_workspace_tools"]
