"""Compatibility entry point for the existing Render start command.

Always starts the OAuth-protected application. The broker package is loaded by
broker_adapter from its installed distribution, rather than importing this file.
"""
import os
import uvicorn
from app import app


class OAuthEntrypoint:
    def run(self, transport="streamable-http", **kwargs):
        if transport != "streamable-http":
            raise ValueError("This entry point supports the OAuth HTTP service only")
        uvicorn.run(
            app, host="0.0.0.0",
            port=int(kwargs.get("port", os.environ.get("PORT", "10000"))),
            access_log=False,
        )


mcp = OAuthEntrypoint()


def main():
    mcp.run()


if __name__ == "__main__":
    main()
