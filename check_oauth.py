"""Check public OAuth discovery configuration without accessing account data."""
import httpx
from oauth import OAuthConfig


def main():
    config = OAuthConfig.from_env()
    if not config.ready:
        raise SystemExit("Set OAUTH_ISSUER and OAUTH_ALLOWED_SUBJECT before checking OAuth")
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        r = client.get(config.resource + "/.well-known/oauth-protected-resource")
        r.raise_for_status()
        resource = r.json()
        if resource.get("resource") != config.resource or resource.get("authorization_servers") != [config.issuer]:
            raise SystemExit("Resource identifier or authorization issuer mismatch")
        metadata = None
        for path in ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]:
            r = client.get(config.issuer.rstrip("/") + path)
            if r.status_code == 200:
                metadata = r.json()
                break
        if not metadata or metadata.get("issuer") != config.issuer:
            raise SystemExit("Authorization server discovery is missing or issuer differs")
        if "S256" not in metadata.get("code_challenge_methods_supported", []):
            raise SystemExit("Authorization server must advertise S256 PKCE")
        for key in ["authorization_endpoint", "token_endpoint"]:
            if not metadata.get(key, "").startswith("https://"):
                raise SystemExit("Authorization/token endpoints must be HTTPS")
        r = client.post(config.resource + "/mcp")
        if r.status_code != 401 or "resource_metadata=" not in r.headers.get("www-authenticate", ""):
            raise SystemExit("MCP endpoint did not return the expected OAuth challenge")
    print("Public discovery and OAuth challenge passed. Now test ChatGPT login and consent.")


if __name__ == "__main__":
    main()
