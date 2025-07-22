from langchain_core.tools import tool


@tool
def search(query: str) -> str:
    """Search for the weather."""
    return f"The weather for {query} is sunny."
