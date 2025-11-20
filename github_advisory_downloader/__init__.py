"""
GitHub Advisory Downloader - A comprehensive tool for downloading and analyzing security advisories.
"""

__version__ = "2.0.0"
__author__ = "Jarlath Bloom"

from .exceptions import (
    GitHubAdvisoryDownloaderException,
    GitHubAPIError,
    CISAError,
    DataProcessingError,
    ConfigurationError,
    ValidationError,
)
from .config import Config
from .github_api import GitHubAdvisoryClient
from .cisa_api import CISAKEVClient
from .data_processing import AdvisoryProcessor
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
