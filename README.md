# Psagot remote MCP

Read-only Psagot Trade integration based on [spark-ordernet-mcp](https://github.com/anhermon/spark-ordernet-mcp).

## Existing Render service

Adding render.yaml does not automatically change the configuration of an existing service created outside a Blueprint. Set these fields in Render Settings:

- Build Command: `pip install -r requirements.txt`
- Start Command: `python app.py`
- Health Check Path: `/healthz`

Set ORDERNET_BROKER=psagot, ORDERNET_USERNAME and ORDERNET_PASSWORD privately in Render Environment. Set MCP_ACCESS_TOKEN to a long random secret (for example, generate locally with `python -c "import secrets; print(secrets.token_urlsafe(32))"`). Never commit credentials or paste them into chat.

Deploy the latest commit. Connect an MCP client to https://psagot-mcp-personal.onrender.com/mcp using the Authorization header with value `Bearer <MCP_ACCESS_TOKEN>`. Client support for custom authorization headers is required. This service does not implement OAuth; a client requiring OAuth will need a separate OAuth integration.

For a new service, use the Render Blueprint in render.yaml. Do not create a duplicate service when updating the existing service.

## Verification

Local verification passed for health, missing-token configuration (503), unauthorized access (401), authenticated MCP initialize, and tools/list (11 read-only tools). Broker authentication and production deployment still require verification after Render configuration.

Account data is protected by the access token. The health endpoint is public and contains no account information. HTTP access logging is disabled. Broker GET requests are restricted by the upstream allowlist; no trade-submission tools are exposed.
