from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from .langgraph.agent import assistant_ui_graph
from .add_langgraph_route import add_langgraph_route
from .routers.oauth_router import router as oauth_router

app = FastAPI(
    title="AI Assistant Backend with Tools",
    description="""
    A FastAPI backend with LangGraph agent supporting Google Workspace and Shopify integrations.

    ## Features
    - **Streaming Chat**: Real-time conversation with AI assistant
    - **Google Workspace Tools**: 21 tools for Docs, Sheets, Drive, Calendar, Gmail, Slides, Meet
    - **Shopify Tools**: 10 tools for products, inventory, customers, orders
    - **JWT Authentication**: Supabase JWT token validation
    - **OAuth2 Flow**: Complete Google Workspace authentication
    - **Extensible Architecture**: Easy to add new tool providers

    ## Authentication
    - Supabase JWT authentication for API access
    - OAuth2 flows for external services (Google Workspace)
    - User-specific credential management
    """,
    version="2.0.0"
)

app.include_router(oauth_router)
# cors
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

add_langgraph_route(app, assistant_ui_graph, "/api/chat")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
