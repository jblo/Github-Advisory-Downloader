"""
Configuration management for GitHub Advisory Downloader.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Set

from dotenv import load_dotenv

from .exceptions import ConfigurationError

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration for GitHub Advisory Downloader."""

    # GitHub API settings
    github_token: Optional[str] = None
    github_api_url: str = "https://api.github.com/graphql"
    github_timeout: int = 30

    # CISA KEV settings
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    cisa_timeout: int = 30
    cisa_cache_ttl: int = 3600  # Cache for 1 hour
    cisa_cache_dir: Optional[Path] = None

    # Output settings
    output_dir: Path = field(default_factory=lambda: Path("github_advisories_output"))
    output_formats: Set[str] = field(default_factory=lambda: {"csv", "json"})
    timestamp_outputs: bool = True

    # Processing settings
    batch_size: int = 100
    max_retries: int = 3
    retry_delay: int = 5

    # Feature flags
    create_csv: bool = True
    create_json: bool = True
    create_summary: bool = True
    dry_run: bool = False
    debug: bool = False

    # Filtering settings
    severity_filter: Optional[Set[str]] = None

    # User agent
    user_agent: str = "GitHub-Advisory-Downloader"

    @classmethod
    def from_env_and_args(cls, **kwargs) -> "Config":
        """
        Create Config from environment variables and CLI arguments.

        Args:
            **kwargs: Override values from environment variables

        Returns:
            Config: Configuration instance

        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Load .env file if it exists
        load_dotenv()

        # Get values from environment or use defaults
        config_dict = {
            "github_token": os.getenv("GITHUB_TOKEN"),
            "output_dir": Path(os.getenv("OUTPUT_DIR", "github_advisories_output")),
            "cisa_cache_dir": (
                Path(os.getenv("CISA_CACHE_DIR", ".cache"))
                if os.getenv("CISA_CACHE_DIR")
                else None
            ),
            "debug": os.getenv("DEBUG", "false").lower() == "true",
            "dry_run": os.getenv("DRY_RUN", "false").lower() == "true",
            "batch_size": int(os.getenv("BATCH_SIZE", "100")),
        }

        # Override with CLI arguments
        config_dict.update(kwargs)

        try:
            config = cls(**config_dict)
            config.validate()
            return config
        except (TypeError, ValueError) as e:
            raise ConfigurationError(f"Invalid configuration: {e}") from e

    def validate(self) -> None:
        """
        Validate configuration.

        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate output directory
        try:
            self.output_dir = Path(self.output_dir)
            if not self.dry_run:
                self.output_dir.mkdir(parents=True, exist_ok=True)
                if not os.access(self.output_dir, os.W_OK):
                    raise ConfigurationError(
                        f"Output directory not writable: {self.output_dir}"
                    )
        except Exception as e:
            raise ConfigurationError(f"Invalid output directory: {e}") from e

        # Validate cache directory if specified
        if self.cisa_cache_dir:
            try:
                self.cisa_cache_dir = Path(self.cisa_cache_dir)
                if not self.dry_run:
                    self.cisa_cache_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise ConfigurationError(f"Invalid cache directory: {e}") from e

        # Validate batch size
        if self.batch_size < 1 or self.batch_size > 100:
            raise ConfigurationError(
                f"Batch size must be between 1 and 100, got {self.batch_size}"
            )

        # Validate severity filter
        valid_severities = {"CRITICAL", "HIGH", "MODERATE", "LOW"}
        if self.severity_filter:
            invalid = self.severity_filter - valid_severities
            if invalid:
                raise ConfigurationError(f"Invalid severities: {invalid}")

        # Warn about token in CLI
        if "github_token" in os.environ and os.getenv("DEBUG"):
            logger.warning(
                "⚠️  GitHub token passed via CLI. Consider using GITHUB_TOKEN environment variable instead."
            )

        logger.debug(
            f"Configuration validated: output_dir={self.output_dir}, batch_size={self.batch_size}"
        )

    def __repr__(self) -> str:
        """Return string representation with masked token."""
        attrs = {
            "github_token": "***" if self.github_token else None,
            "output_dir": str(self.output_dir),
            "output_formats": self.output_formats,
            "batch_size": self.batch_size,
            "debug": self.debug,
            "dry_run": self.dry_run,
        }
        return f"Config({', '.join(f'{k}={v}' for k, v in attrs.items() if v is not None)})"
