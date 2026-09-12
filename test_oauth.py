"""Offline checks; no real broker login, credentials, or live orders."""
import asyncio
import json
import os
import time
import unittest

# Test requests never use the host's outbound proxy.
for name in list(os.environ):
    if name.lower().endswith("_proxy"):
        os.environ.pop(name)

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient
from app import create_app
from oauth import JWTVerifier, OAuthConfig, https_origin

CONFIG = OAuthConfig("https://test-identity.example/", "https://psagot-mcp-personal.onrender.com", "test-owner")
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key())), "kid": "key-1", "alg": "RS256", "use": "sig"}


def token(**changes):
    claims = dict(iss=CONFIG.issuer, aud=CONFIG.resource, sub=CONFIG.subject,
                  iat=int(time.time()) - 1, exp=int(time.time()) + 300,
                  scope=CONFIG.scope, azp="test-client")
    claims.update(changes)
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "key-1"})


class VerificationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.calls = 0
        self.response_keys = [JWK]

        def jwks(request):
            self.calls += 1
            self.assertEqual(str(request.url), CONFIG.issuer + ".well-known/jwks.json")
            return httpx.Response(200, json={"keys": self.response_keys})

        self.verifier = JWTVerifier(CONFIG, httpx.MockTransport(jwks))

    async def test_valid_owner_and_cache(self):
        result = await self.verifier.verify_token(token())
        self.assertEqual(result.subject, CONFIG.subject)
        self.assertEqual(result.resource, CONFIG.resource)
        self.assertIsNotNone(await self.verifier.verify_token(token()))
        self.assertEqual(self.calls, 1)

    async def test_other_user_rejected(self):
        self.assertIsNone(await self.verifier.verify_token(token(sub="other-owner")))

    async def test_wrong_issuer_and_audience_rejected(self):
        for change in [{"iss": "https://other.example/"}, {"aud": "another-api"}]:
            self.assertIsNone(await self.verifier.verify_token(token(**change)))

    async def test_expiration_and_not_before(self):
        for change in [{"exp": int(time.time()) - 10}, {"nbf": int(time.time()) + 100}]:
            self.assertIsNone(await self.verifier.verify_token(token(**change)))

    async def test_missing_expiration(self):
        claims = jwt.decode(token(), options={"verify_signature": False})
        del claims["exp"]
        signed = jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "key-1"})
        self.assertIsNone(await self.verifier.verify_token(signed))

    async def test_scope_required(self):
        for scope in ["", "portfolio:write", ["portfolio:read"]]:
            self.assertIsNone(await self.verifier.verify_token(token(scope=scope)))

    async def test_signature_and_algorithm_rejected(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        claims = jwt.decode(token(), options={"verify_signature": False})
        bad = jwt.encode(claims, other, algorithm="RS256", headers={"kid": "key-1"})
        self.assertIsNone(await self.verifier.verify_token(bad))
        bad = jwt.encode(claims, "test-hmac-key", algorithm="HS256", headers={"kid": "key-1"})
        self.assertIsNone(await self.verifier.verify_token(bad))

    async def test_unknown_key_fetches_are_bounded(self):
        claims = jwt.decode(token(), options={"verify_signature": False})
        bad = jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "unknown"})
        for _ in range(3):
            self.assertIsNone(await self.verifier.verify_token(bad))
        self.assertEqual(self.calls, 1)

    async def test_rotated_key_can_be_loaded(self):
        self.assertIsNotNone(await self.verifier.verify_token(token()))
        self.response_keys = [{**JWK, "kid": "key-2"}]
        self.verifier.last_attempt -= 31
        claims = jwt.decode(token(), options={"verify_signature": False})
        rotated = jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "key-2"})
        self.assertIsNotNone(await self.verifier.verify_token(rotated))

    async def test_provider_outage_and_bad_jwks(self):
        for response in [httpx.Response(503), httpx.Response(200, text="not-json"),
                         httpx.Response(200, text="x" * 65537)]:
            v = JWTVerifier(CONFIG, httpx.MockTransport(lambda request: response))
            self.assertIsNone(await v.verify_token(token()))


class HTTPTests(unittest.TestCase):
    def test_discovery_and_unauthorized_challenge(self):
        verifier = JWTVerifier(CONFIG, httpx.MockTransport(lambda request: httpx.Response(200, json={"keys": [JWK]})))
        with TestClient(create_app(CONFIG, verifier)) as c:
            r = c.get("/.well-known/oauth-protected-resource")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["authorization_servers"], [CONFIG.issuer])
            self.assertEqual(r.json()["resource"], CONFIG.resource)
            self.assertIn(CONFIG.scope, r.json()["scopes_supported"])
            r = c.post("/mcp")
            self.assertEqual(r.status_code, 401)
            self.assertIn("resource_metadata=", r.headers["www-authenticate"])
            r = c.post("/mcp", headers={"Authorization": "Bearer old-static-token"})
            self.assertEqual(r.status_code, 401)

    def test_authenticated_mcp_initialization_and_tool_policies(self):
        verifier = JWTVerifier(CONFIG, httpx.MockTransport(lambda request: httpx.Response(200, json={"keys": [JWK]})))
        with TestClient(create_app(CONFIG, verifier)) as c:
            headers = {"Authorization": "Bearer " + token(), "Accept": "application/json, text/event-stream"}
            r = c.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}})
            self.assertEqual(r.status_code, 200)
            r = c.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            self.assertEqual(r.status_code, 200)
            tools = r.json()["result"]["tools"]
            self.assertEqual(len(tools), 11)
            for tool in tools:
                self.assertTrue(tool["annotations"]["readOnlyHint"])
                self.assertEqual(tool["_meta"]["securitySchemes"], [{"type": "oauth2", "scopes": [CONFIG.scope]}])

    def test_missing_configuration_is_closed(self):
        with TestClient(create_app(OAuthConfig("", CONFIG.resource, ""))) as c:
            self.assertEqual(c.get("/healthz").status_code, 200)
            self.assertFalse(c.get("/healthz").json()["oauth_configured"])
            self.assertEqual(c.post("/mcp").status_code, 503)
            self.assertEqual(c.get("/.well-known/oauth-protected-resource").status_code, 503)

    def test_invalid_configuration_urls(self):
        for value in ["http://id.example", "https://user:password@id.example", "https://id.example/?token=x", "https://id.example/path"]:
            with self.assertRaises(ValueError):
                https_origin(value)


if __name__ == "__main__":
    unittest.main()
