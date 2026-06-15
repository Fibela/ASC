"""AscClient — async HTTP client for the ASC PremosCorp API.

Authentication: X-API-Key header (API keys created via POST /api/v1/api-keys/).
All methods are async. Use as an async context manager or call .close() explicitly.

Example:
    async with AscClient(api_key="asc_abc12345_...") as client:
        incidents = await client.incidents.list()
        hook = await client.webhooks.create(
            url="https://my-server.com/webhook",
            events=["incident.created", "alert.critical"],
        )
        print(hook.secret)  # shown once — store securely
"""
from __future__ import annotations

import httpx

from .exceptions import (
    AscError,
    AuthError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from .resources.alerts import AlertsResource
from .resources.api_keys import APIKeysResource
from .resources.events import EventsResource
from .resources.incidents import IncidentsResource
from .resources.webhooks import WebhooksResource

_DEFAULT_BASE_URL = "https://asc.premoscorp.com"
_DEFAULT_TIMEOUT = 30.0
_SDK_VERSION = "0.1.0"


def _raise_for_status(response: httpx.Response) -> None:
    """Map HTTP error status codes to typed SDK exceptions."""
    if response.is_success:
        return
    body: dict = {}
    try:
        body = response.json()
    except Exception:
        pass
    detail: str = body.get("detail", response.text or "Unknown error")
    sc = response.status_code

    if sc == 401:
        raise AuthError(f"Authentication failed: {detail}", status_code=sc, response=body)
    if sc == 403:
        raise ForbiddenError(f"Forbidden: {detail}", status_code=sc, response=body)
    if sc == 404:
        raise NotFoundError(f"Not found: {detail}", status_code=sc, response=body)
    if sc == 422:
        raise ValidationError(f"Validation error: {detail}", status_code=sc, response=body)
    if sc == 429:
        retry_after = int(response.headers.get("Retry-After", 60))
        raise RateLimitError(
            f"Rate limit exceeded: {detail}",
            retry_after=retry_after,
            status_code=sc,
            response=body,
        )
    if sc >= 500:
        raise ServerError(f"Server error {sc}: {detail}", status_code=sc, response=body)
    raise AscError(f"HTTP {sc}: {detail}", status_code=sc, response=body)


class AscClient:
    """
    Async Python client for the ASC PremosCorp SOC Platform API.

    Parameters
    ----------
    api_key:  API key string (format: asc_<8-char-prefix>_<secret>)
    base_url: Override the default production endpoint
    timeout:  Per-request timeout in seconds (default 30)
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "X-API-Key": api_key,
                "Accept": "application/json",
                "User-Agent": f"asc-sdk-python/{_SDK_VERSION}",
            },
            timeout=timeout,
        )
        self.incidents = IncidentsResource(self)
        self.alerts = AlertsResource(self)
        self.events = EventsResource(self)
        self.api_keys = APIKeysResource(self)
        self.webhooks = WebhooksResource(self)

    async def _request(
        self, method: str, path: str, **kwargs
    ) -> dict | list:
        response = await self._http.request(method, path, **kwargs)
        _raise_for_status(response)
        if response.status_code == 204:
            return {}
        return response.json()

    async def close(self) -> None:
        """Release the underlying httpx connection pool."""
        await self._http.aclose()

    async def __aenter__(self) -> "AscClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()
