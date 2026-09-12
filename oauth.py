"""OAuth resource-server verification; login and refresh belong to the IdP."""
import asyncio
from dataclasses import dataclass
import json
import os
import time
from urllib.parse import urlsplit

import httpx
import jwt
from mcp.server.auth.provider import AccessToken


def https_origin(value):
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ("", "/")
            or url.port not in (None, 443)):
        raise ValueError("OAuth URLs must be HTTPS origins without credentials or query strings")
    return value


@dataclass(frozen=True)
class OAuthConfig:
    issuer: str
    resource: str
    subject: str
    scope: str = "portfolio:read"

    @property
    def ready(self):
        return bool(self.issuer and self.subject)

    @classmethod
    def from_env(cls):
        issuer = os.environ.get("OAUTH_ISSUER", "").strip()
        resource = os.environ.get("PUBLIC_BASE_URL", "https://psagot-mcp-personal.onrender.com").rstrip("/")
        https_origin(resource)
        if issuer:
            https_origin(issuer)
        return cls(issuer, resource, os.environ.get("OAUTH_ALLOWED_SUBJECT", "").strip())


class JWTVerifier:
    def __init__(self, config, transport=None):
        self.config = config
        self.transport = transport
        self.keys = {}
        self.loaded_at = float("-inf")
        self.last_attempt = float("-inf")
        self.lock = asyncio.Lock()

    async def signing_key(self, kid):
        now = time.monotonic()
        if kid in self.keys and now - self.loaded_at < 300:
            return self.keys[kid]
        async with self.lock:
            now = time.monotonic()
            if kid in self.keys and now - self.loaded_at < 300:
                return self.keys[kid]
            # Bound unknown-key requests and retries during a provider outage.
            if now - self.last_attempt < 30:
                return None
            self.last_attempt = now
            async with httpx.AsyncClient(
                transport=self.transport, timeout=10, follow_redirects=False,
            ) as client:
                async with client.stream("GET", self.config.issuer.rstrip("/") + "/.well-known/jwks.json") as response:
                    response.raise_for_status()
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > 65536:
                            raise ValueError("JWKS response exceeds size limit")
            jwks = json.loads(data)
            entries = jwks.get("keys", [])
            if not isinstance(entries, list) or len(entries) > 32:
                raise ValueError("Invalid JWKS")
            keys = {}
            for entry in entries:
                if (entry.get("kty") == "RSA" and entry.get("use", "sig") == "sig"
                        and entry.get("alg", "RS256") == "RS256" and entry.get("kid")):
                    key = jwt.PyJWK.from_dict(entry, algorithm="RS256").key
                    if key.key_size >= 2048:
                        keys[entry["kid"]] = key
            self.keys = keys
            self.loaded_at = now
            return keys.get(kid)

    async def verify_token(self, token):
        if not self.config.ready or len(token) > 16384:
            return None
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if header.get("alg") != "RS256" or not isinstance(kid, str) or len(kid) > 128:
                return None
            key = await self.signing_key(kid)
            if key is None:
                return None
            claims = jwt.decode(
                token, key, algorithms=["RS256"],
                issuer=self.config.issuer, audience=self.config.resource,
                options={"require": ["iss", "aud", "exp", "iat", "sub"]},
            )
            # One shared broker account: a valid login alone is insufficient.
            if claims["sub"] != self.config.subject:
                return None
            scope = claims.get("scope", "")
            if not isinstance(scope, str) or self.config.scope not in scope.split():
                return None
            client_id = claims.get("azp", claims.get("client_id", ""))
            if not isinstance(client_id, str):
                return None
            return AccessToken(
                token=token, client_id=client_id, scopes=scope.split(),
                expires_at=int(claims["exp"]), resource=self.config.resource,
                subject=claims["sub"],
            )
        except (jwt.PyJWTError, httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
            # Never log tokens, response bodies, subjects, or broker credentials.
            return None
