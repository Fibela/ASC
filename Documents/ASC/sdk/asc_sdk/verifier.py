"""WebhookVerifier — constant-time HMAC-SHA256 signature verification.

Usage in your webhook receiver endpoint:

    from asc_sdk import WebhookVerifier
    from asc_sdk.exceptions import InvalidSignatureError

    verifier = WebhookVerifier(secret="<your-webhook-secret>")

    # In your HTTP handler:
    body: bytes = await request.body()
    signature: str = request.headers.get("X-ASC-Signature", "")

    try:
        event = verifier.parse_event(body, signature)
        print(event["event"], event["data"])
    except InvalidSignatureError:
        return Response(status=403)

Verification algorithm (identical to the ASC backend dispatcher):
    expected = "sha256=" + HMAC-SHA256(secret, body).hexdigest()
    hmac.compare_digest(expected, signature)   # constant-time
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from .exceptions import InvalidSignatureError


class WebhookVerifier:
    """Verify and parse incoming ASC PremosCorp webhook deliveries."""

    def __init__(self, secret: str) -> None:
        self._secret = secret

    def verify(self, body: bytes, signature: str) -> bool:
        """Return True iff `signature` is the valid HMAC-SHA256 of `body`."""
        expected = "sha256=" + hmac.new(
            self._secret.encode(), body, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def parse_event(self, body: bytes, signature: str) -> dict[str, Any]:
        """
        Verify signature and return the parsed JSON payload.

        Raises InvalidSignatureError if verification fails — treat the
        delivery as a forgery attempt and return HTTP 403 to the sender.
        """
        if not self.verify(body, signature):
            raise InvalidSignatureError(
                "Webhook signature verification failed — "
                "check that the secret matches the one shown at registration"
            )
        return json.loads(body)
