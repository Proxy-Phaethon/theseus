## Internet-specific errors

class InternetError(Exception):
    """Base exception for the Internet layer."""

class RequestError(InternetError):
    """Raised when an HTTP request fails."""