"""Read-only Psagot MCP resource server with OAuth authentication."""
import os
os.environ.setdefault("ORDERNET_BROKER", "psagot")

from ordernet_mcp import mcp as upstream
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn
from oauth import OAuthConfig, JWTVerifier


def create_app(config=None, verifier=None):
    config = config or OAuthConfig.from_env()
    tools = []
    # Both versions are pinned. Preserve upstream's explicit broker GET allowlist.
    for tool in upstream._tool_manager.list_tools():
        tools.append(tool.model_copy(update={
            "meta": {**(tool.meta or {}), "securitySchemes": [
                {"type": "oauth2", "scopes": [config.scope]}
            ]},
            "annotations": ToolAnnotations(readOnlyHint=True, destructiveHint=False),
        }))
    server = MCPServer(
        "psagot-trade", tools=tools,
        token_verifier=verifier or JWTVerifier(config),
        auth=AuthSettings(
            issuer_url=config.issuer or config.resource,
            resource_server_url=config.resource,
            validate_token_resource=True,
            required_scopes=[config.scope],
        ),
    )
    inner = server.streamable_http_app(
        host="0.0.0.0", streamable_http_path="/mcp",
        stateless_http=True, json_response=True,
    )

    async def health(request):
        return JSONResponse({"status": "ok", "oauth_configured": config.ready})

    inner.routes.insert(0, Route("/healthz", health))

    async def app(scope, receive, send):
        if scope["type"] == "http" and scope["path"] != "/healthz" and not config.ready:
            return await JSONResponse(
                {"error": "OAuth configuration is incomplete"}, status_code=503,
                headers={"Cache-Control": "no-store"},
            )(scope, receive, send)
        return await inner(scope, receive, send)

    return app


app = create_app()
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), access_log=False)
