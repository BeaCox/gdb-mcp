import asyncio
import unittest

from mcp.server.fastmcp import FastMCP
from starlette.testclient import TestClient

from gdb_mcp.http_security import configure_http_security, is_loopback_host


class HttpSecurityTests(unittest.TestCase):
    def test_loopback_detection_is_conservative(self) -> None:
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertFalse(is_loopback_host("0.0.0.0"))
        self.assertFalse(is_loopback_host("debug.example.com"))

    def test_non_loopback_bind_requires_explicit_protection(self) -> None:
        with self.assertRaisesRegex(ValueError, "refusing non-loopback"):
            configure_http_security(
                FastMCP("test"),
                transport="streamable-http",
                host="0.0.0.0",
                allow_remote=False,
                allow_unsafe_over_http=False,
                unsafe_enabled=False,
                bearer_token=None,
                issuer_url=None,
                resource_url=None,
                allowed_hosts=[],
                allowed_origins=[],
            )

    def test_non_loopback_bind_requires_authentication_and_host_allow_list(self) -> None:
        common = {
            "transport": "streamable-http",
            "host": "0.0.0.0",
            "allow_remote": True,
            "allow_unsafe_over_http": False,
            "unsafe_enabled": False,
            "allowed_origins": [],
        }
        with self.assertRaisesRegex(ValueError, "requires bearer authentication"):
            configure_http_security(
                FastMCP("test"),
                **common,
                bearer_token=None,
                issuer_url=None,
                resource_url=None,
                allowed_hosts=[],
            )
        with self.assertRaisesRegex(ValueError, "requires at least one --http-allowed-host"):
            configure_http_security(
                FastMCP("test"),
                **common,
                bearer_token="secret",
                issuer_url="https://issuer.example.com",
                resource_url="https://debug.example.com/mcp",
                allowed_hosts=[],
            )

    def test_non_loopback_unsafe_tools_need_separate_acknowledgement(self) -> None:
        with self.assertRaisesRegex(ValueError, "allow-unsafe-over-http"):
            configure_http_security(
                FastMCP("test"),
                transport="streamable-http",
                host="0.0.0.0",
                allow_remote=True,
                allow_unsafe_over_http=False,
                unsafe_enabled=True,
                bearer_token="secret",
                issuer_url="https://issuer.example.com",
                resource_url="https://debug.example.com/mcp",
                allowed_hosts=["debug.example.com:*"],
                allowed_origins=[],
            )

    def test_bearer_authentication_rejects_missing_token_and_accepts_valid_token(self) -> None:
        server = FastMCP("http-security-test")
        configure_http_security(
            server,
            transport="streamable-http",
            host="0.0.0.0",
            allow_remote=True,
            allow_unsafe_over_http=False,
            unsafe_enabled=False,
            bearer_token="test-secret",
            issuer_url="https://issuer.example.com",
            resource_url="https://debug.example.com/mcp",
            allowed_hosts=["debug.example.com:*"],
            allowed_origins=[],
        )

        self.assertIsNone(asyncio.run(server._token_verifier.verify_token("wrong")))
        self.assertIsNotNone(asyncio.run(server._token_verifier.verify_token("test-secret")))

        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        }
        headers = {
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
            "host": "debug.example.com:443",
        }
        with TestClient(server.streamable_http_app()) as client:
            rejected = client.post("/mcp", headers=headers, json=initialize)
            accepted = client.post(
                "/mcp",
                headers={**headers, "authorization": "Bearer test-secret"},
                json=initialize,
            )

        self.assertEqual(rejected.status_code, 401)
        self.assertIn("Bearer", rejected.headers["www-authenticate"])
        self.assertEqual(accepted.status_code, 200)
        self.assertIn('"capabilities"', accepted.text)


if __name__ == "__main__":
    unittest.main()
