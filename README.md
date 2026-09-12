# Psagot Trade MCP with OAuth

Read-only personal Psagot account access for an OAuth-linked ChatGPT connection. Login, consent, authorization-code exchange with PKCE, and refresh-token management are delegated to an external identity provider such as Auth0. This repository implements the MCP resource server, not a standalone authorization server.

## What changed

Static MCP_ACCESS_TOKEN authentication has been removed. The server now publishes OAuth protected-resource metadata, returns an OAuth discovery challenge on unauthenticated MCP requests, and validates RS256 access-token signatures against the configured issuer's JWKS. It checks issuer, audience, expiration, not-before, required claims, the portfolio:read scope, and an exact owner subject. Another authenticated user is denied because the broker account is shared by the server process.

All 11 upstream tools preserve the broker GET allowlist and declare OAuth scopes and read-only annotations. Tokens and broker credentials are never logged. Access tokens expire according to the identity provider's policy; use short-lived tokens. Local JWT validation cannot instantly revoke an already-issued access token. To disconnect immediately, change/remove OAUTH_ALLOWED_SUBJECT and redeploy.

## Configure your personal identity provider

Use a personal Auth0 tenant configured for MCP authorization following the official guides:
- https://developers.openai.com/plugins/build/auth
- https://auth0.com/ai/docs/mcp

Create an RS256 API with identifier exactly:
https://psagot-mcp-personal.onrender.com

Define the permission portfolio:read. Configure authorization-code + S256 PKCE login and consent for ChatGPT, using supported MCP client registration (CIMD/DCR) or a predefined OAuth application. For a predefined application, copy the exact callback URL from ChatGPT's connection setup into the application's allowed callback URLs; do not guess it. Enable the appropriate user login connection.

Ensure the provider's discovery metadata advertises S256 and supports the resource parameter for this API, or configure its default audience to this exact API identifier where the provider's documented MCP setup requires that. ChatGPT sends resource, not an Auth0-specific audience parameter. The issued access token must include the API audience and portfolio:read scope.

Find your own Auth0 user's User ID, such as auth0|... or google-oauth2|..., and store it as OAUTH_ALLOWED_SUBJECT. The allowlist checks this exact subject; email matching alone is not used.

## Render configuration

For the existing service, set these fields manually in Render Settings (committing render.yaml does not alter an existing non-Blueprint service):
- Build Command: pip install -r requirements.txt
- Start Command: python app.py
- Health Check Path: /healthz

Set these Environment values:
- PUBLIC_BASE_URL=https://psagot-mcp-personal.onrender.com
- OAUTH_ISSUER=https://YOUR-PERSONAL-TENANT.auth0.com/ (must exactly match the token iss and provider metadata; preserve the trailing slash)
- OAUTH_ALLOWED_SUBJECT=your exact user subject
- ORDERNET_BROKER=psagot
- ORDERNET_USERNAME and ORDERNET_PASSWORD, entered privately in Render

No static MCP_ACCESS_TOKEN is needed. Existing unused values can be removed in the Dashboard. Without issuer or allowed subject, /mcp and discovery return 503; only /healthz remains accessible and reports oauth_configured=false. Invalid issuer/base URL configuration fails startup.

Deploy, then run python check_oauth.py to validate public discovery configuration. It never requests broker account data.

In ChatGPT, create an OAuth connection for:
https://psagot-mcp-personal.onrender.com/mcp

Complete the identity provider's login/consent screen. ChatGPT receives OAuth tokens through this flow, rather than a token pasted into a chat. If using a predefined OAuth client, enter its credentials only in the connection's dedicated OAuth settings.

## Verification

Run: python -m unittest -q test_oauth

14 offline tests cover OAuth metadata/challenges, authenticated MCP initialize and discovery of all 11 tools, required owner and scope, issuer and audience, expiration/not-before, missing expiration, wrong signature/algorithm, JWKS caching, key rotation, bounded unknown-key fetching, provider outages, malformed/oversized JWKS, missing configuration, and invalid URLs.

These checks do not prove live identity-provider login, PKCE/code exchange, refresh, ChatGPT connection behavior, Render deployment, or broker authentication. Those require a configured personal identity provider and a deployed service.

The pinned upstream package provides read-only requests; no live order submission tools are exposed. Dependency upgrades should rerun these checks because tool copying uses the pinned SDK's upstream registry.
