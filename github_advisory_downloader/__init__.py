"""
GitHub Advisory Downloader - A comprehensive tool for downloading and analyzing security advisories.
"""

__version__ = "2.0.0"
__author__ = "Jarlath Bloom"

from .cisa_api import CISAKEVClient
from .config import Config
from .data_processing import AdvisoryProcessor
from .exceptions import (
    CISAError,
    ConfigurationError,
    DataProcessingError,
    GitHubAdvisoryDownloaderException,
    GitHubAPIError,
    ValidationError,
)
from .github_api import GitHubAdvisoryClient
from .output import OutputGenerator

__all__ = [
    "Config",
    "GitHubAdvisoryClient",
    "CISAKEVClient",
    "AdvisoryProcessor",
    "OutputGenerator",
    "GitHubAdvisoryDownloaderException",
    "GitHubAPIError",
    "CISAError",
    "DataProcessingError",
    "ConfigurationError",
    "ValidationError",
]
