class RateLimiterError(Exception):
    """
    Base class for all exceptions raised by the rate limit
    """


class TimesLimitDefinitionError(RateLimiterError):
    """
    Raised when the rate limit is defined with a zero or negative number of times.
    """


class TimeWindowDefinitionError(RateLimiterError):
    """
    Raised when the time window is defined with a zero or negative number of milliseconds.
    """  # noqa: E501


class TimesLimitError(RateLimiterError):
    """
    Raised when the rate limit is hit.
    """


class WindowCheckError(RateLimiterError):
    """
    Raised when the window check fails.
    """


class FixedWindowCheckError(WindowCheckError):
    """
    Raised when the fixed window check fails.
    """


class SlidingWindowCheckError(WindowCheckError):
    """
    Raised when the sliding window check fails.
    """


class ElasticWindowCheckError(WindowCheckError):
    """
    Raised when the elastic window check fails.
    """
