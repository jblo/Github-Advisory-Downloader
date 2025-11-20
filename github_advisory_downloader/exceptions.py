"""
Custom exceptions for GitHub Advisory Downloader.
"""


class GitHubAdvisoryDownloaderException(Exception):
    """Base exception for GitHub Advisory Downloader."""
    pass


class GitHubAPIError(GitHubAdvisoryDownloaderException):
    """Exception raised when GitHub API calls fail."""
    pass


class CISAError(GitHubAdvisoryDownloaderException):
    """Exception raised when CISA KEV API calls fail."""
    pass


class DataProcessingError(GitHubAdvisoryDownloaderException):
    """Exception raised during data processing."""
    pass


class ConfigurationError(GitHubAdvisoryDownloaderException):
    """Exception raised when configuration is invalid."""
    pass


class ValidationError(GitHubAdvisoryDownloaderException):
    """Exception raised when data validation fails."""
    pass
