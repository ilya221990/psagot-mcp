"""Authenticated, read-only Psagot MCP HTTP entry point."""
import hmac
import os

os.environ.setdefault("ORDERNET_BROKER", "psagot")

from ordernet_mcp import mcp
from starlette.responses import JSONResponse
import uvicorn

inner = mcp.streamable_http_app(
    host="0.0.0.0",
    streamable_http_path="/mcp",
    stateless_http=True,
    json_response=True,
)

class ProtectedApp:
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await inner(scope, receive, send)
        if scope["path"] == "/healthz":
            return await JSONResponse({"status": "ok"})(scope, receive, send)
        token = os.environ.get("MCP_ACCESS_TOKEN", "")
        headers = dict(scope.get("headers", []))
        supplied = headers.get(b"authorization", b"").decode("latin-1")
        if not token:
            return await JSONResponse({"error": "MCP access is not configured"}, status_code=503)(scope, receive, send)
        if not hmac.compare_digest(supplied.encode(), ("Bearer " + token).encode()):
            return await JSONResponse({"error": "Unauthorized"}, status_code=401)(scope, receive, send)
        return await inner(scope, receive, send)

app = ProtectedApp()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), access_log=False)
