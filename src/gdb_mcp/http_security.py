"""Security policy and bearer-token support for HTTP MCP transports."""

from __future__ import annotations

import ipaddress
import secrets
from typing import Any

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

HTTP_TRANSPORTS = frozenset({"sse", "streamable-http"})


class StaticBearerTokenVerifier:
    """Validate one externally managed bearer token without logging its value."""

    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("HTTP bearer token must not be empty")
        self._token = token

    async def verify_token(self, token: str) -> AccessToken | None:
        if not secrets.compare_digest(token, self._token):
            return None
        return AccessToken(
            token=token,
            client_id="gdb-mcp-static-bearer",
            scopes=["gdb-mcp"],
        )


def is_loopback_host(host: str) -> bool:
    """Return whether a bind target is unambiguously local."""

    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def configure_http_security(
    mcp: FastMCP[Any],
    *,
    transport: str,
    host: str,
    allow_remote: bool,
    allow_unsafe_over_http: bool,
    unsafe_enabled: bool,
    bearer_token: str | None,
    issuer_url: str | None,
    resource_url: str | None,
    allowed_hosts: list[str],
    allowed_origins: list[str],
) -> None:
    """Validate an HTTP deployment and configure its transport protections.

    Non-loopback listeners need an explicit acknowledgement, authentication, and
    an allow-list for Host headers. The bearer token is deliberately obtained by
    the caller so deployments can source it from a secret manager or environment.
    """

    if transport not in HTTP_TRANSPORTS:
        if any((bearer_token, issuer_url, resource_url, allowed_hosts, allowed_origins)):
            raise ValueError("HTTP security options require an HTTP transport")
        return

    remote = not is_loopback_host(host)
    has_auth_options = any((bearer_token, issuer_url, resource_url))
    if has_auth_options and not all((bearer_token, issuer_url, resource_url)):
        raise ValueError(
            "HTTP bearer authentication requires a token, issuer URL, and resource URL"
        )

    if remote:
        if not allow_remote:
            raise ValueError(
                "refusing non-loopback HTTP bind; pass --allow-remote only for a protected "
                "deployment"
            )
        if not has_auth_options:
            raise ValueError(
                "non-loopback HTTP requires bearer authentication; set GDB_MCP_HTTP_AUTH_TOKEN "
                "and provide --http-auth-issuer-url and --http-auth-resource-url"
            )
        if not allowed_hosts:
            raise ValueError(
                "non-loopback HTTP requires at least one --http-allowed-host for DNS rebinding "
                "protection"
            )
        if unsafe_enabled and not allow_unsafe_over_http:
            raise ValueError(
                "refusing unsafe tools on non-loopback HTTP; pass --allow-unsafe-over-http "
                "only for an isolated, authenticated deployment"
            )

    if allowed_hosts or allowed_origins:
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
        )

    if bearer_token is not None:
        mcp.settings.auth = AuthSettings(
            issuer_url=issuer_url,
            resource_server_url=resource_url,
        )
        mcp._token_verifier = StaticBearerTokenVerifier(bearer_token)
