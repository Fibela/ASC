"""ASC PremosCorp SDK — Exception hierarchy."""


class AscError(Exception):
    """Base exception for all SDK errors."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response or {}


class AuthError(AscError):
    """Raised on 401 Unauthorized — invalid or expired API key."""


class ForbiddenError(AscError):
    """Raised on 403 Forbidden — valid key lacks required permission."""


class NotFoundError(AscError):
    """Raised on 404 Not Found."""


class ValidationError(AscError):
    """Raised on 422 Unprocessable Entity — request schema mismatch."""


class RateLimitError(AscError):
    """
    Raised on 429 Too Many Requests.
    `retry_after` (seconds) is parsed from the Retry-After response header.
    """

    def __init__(
        self,
        message: str,
        retry_after: int = 60,
        **kwargs,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ServerError(AscError):
    """Raised on 5xx Server Error."""


class InvalidSignatureError(AscError):
    """Raised by WebhookVerifier when the X-ASC-Signature does not match."""
