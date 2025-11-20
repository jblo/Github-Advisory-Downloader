"""
GitHub API module for fetching security advisories.
"""

import logging
import time
from typing import Any, Dict, Generator, List, Optional

import requests

from .config import Config
from .exceptions import GitHubAPIError
from .validation import DataValidator

logger = logging.getLogger(__name__)


class GitHubAdvisoryClient:
    """Client for GitHub Security Advisory API."""

    def __init__(self, config: Config):
        """
        Initialize GitHub API client.

        Args:
            config: Configuration instance
        """
        self.config = config
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": self.config.user_agent,
        }
        if config.github_token:
            self.headers["Authorization"] = f"Bearer {config.github_token}"

    def get_advisories(
        self,
        severity_filter: Optional[set] = None,
        checkpoint: Optional[str] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Fetch security advisories from GitHub with pagination.

        Args:
            severity_filter: Optional set of severities to filter (e.g., {"CRITICAL", "HIGH"})
            checkpoint: Cursor to resume from previous download

        Yields:
            Advisory dict for each advisory

        Raises:
            GitHubAPIError: If API calls fail
        """
        cursor = checkpoint
        page = 1

        while True:
            logger.info(f"📄 Fetching page {page}...")

            try:
                query = self._build_query(cursor)
                response = self._execute_query(query)
                data = response.json()

                if "errors" in data:
                    errors = data["errors"]
                    logger.error(f"❌ GraphQL errors: {errors}")
                    raise GitHubAPIError(f"GraphQL errors: {errors}")

                advisories_data = data.get("data", {}).get("securityAdvisories", {})
                advisories = advisories_data.get("nodes", [])

                if not advisories:
                    logger.info(f"📄 Page {page}: No advisories found")
                    break

                logger.info(f"✅ Page {page}: {len(advisories)} advisories")

                # Yield filtered advisories
                for advisory in advisories:
                    try:
                        DataValidator.validate_advisory_response(advisory)

                        severity = advisory.get("severity", "")
                        if severity_filter and severity not in severity_filter:
                            continue

                        yield advisory

                    except Exception as e:
                        logger.warning(f"⚠️  Skipping advisory: {e}")
                        continue

                # Check for more pages
                page_info = advisories_data.get("pageInfo", {})
                if not page_info.get("hasNextPage"):
                    logger.info("📄 All pages fetched")
                    break

                cursor = page_info.get("endCursor")
                page += 1

                # Rate limiting
                time.sleep(0.5)

            except requests.exceptions.RequestException as e:
                logger.error(f"❌ Request failed on page {page}: {e}")
                raise GitHubAPIError(f"Failed to fetch page {page}: {e}") from e
            except Exception as e:
                logger.error(f"❌ Unexpected error on page {page}: {e}")
                raise GitHubAPIError(f"Unexpected error on page {page}: {e}") from e

    def _build_query(self, cursor: Optional[str] = None) -> str:
        """
        Build GraphQL query for fetching advisories.

        Args:
            cursor: Pagination cursor

        Returns:
            GraphQL query string
        """
        after_clause = f', after: "{cursor}"' if cursor else ""

        return f"""
        {{
            securityAdvisories(first: {self.config.batch_size}{after_clause}) {{
                pageInfo {{
                    hasNextPage
                    endCursor
                }}
                nodes {{
                    ghsaId
                    summary
                    description
                    severity
                    publishedAt
                    updatedAt
                    withdrawnAt
                    permalink
                    identifiers {{
                        type
                        value
                    }}
                    references {{
                        url
                    }}
                    vulnerabilities(first: 10) {{
                        nodes {{
                            package {{
                                name
                                ecosystem
                            }}
                            vulnerableVersionRange
                            firstPatchedVersion {{
                                identifier
                            }}
                        }}
                    }}
                    cvss {{
                        score
                        vectorString
                    }}
                }}
            }}
        }}
        """

    def _execute_query(self, query: str, max_retries: int = None) -> requests.Response:
        """
        Execute GraphQL query with retry logic.

        Args:
            query: GraphQL query string
            max_retries: Maximum retry attempts

        Returns:
            Response object

        Raises:
            GitHubAPIError: If all retries fail
        """
        if max_retries is None:
            max_retries = self.config.max_retries

        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.config.github_api_url,
                    headers=self.headers,
                    json={"query": query},
                    timeout=self.config.github_timeout,
                )
                response.raise_for_status()
                return response

            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    wait_time = self.config.retry_delay * (
                        2**attempt
                    )  # Exponential backoff
                    logger.warning(
                        f"⚠️  Attempt {attempt + 1}/{max_retries} failed: {e}. "
                        f"Retrying in {wait_time}s..."
                    )
                    time.sleep(wait_time)
                else:
                    raise GitHubAPIError(
                        f"Failed after {max_retries} attempts: {e}"
                    ) from e

    def get_rate_limit_info(self) -> Dict[str, Any]:
        """
        Get GitHub API rate limit information.

        Returns:
            Dict with rate limit info

        Raises:
            GitHubAPIError: If fetch fails
        """
        query = "{ rateLimit { limit remaining resetAt } }"

        try:
            response = self._execute_query(query, max_retries=1)
            data = response.json()
            rate_limit = data.get("data", {}).get("rateLimit", {})
            return rate_limit
        except Exception as e:
            logger.warning(f"Could not fetch rate limit info: {e}")
            return {}

    def log_rate_limit(self) -> None:
        """Log current rate limit status."""
        rate_limit = self.get_rate_limit_info()
        if rate_limit:
            remaining = rate_limit.get("remaining", "unknown")
            limit = rate_limit.get("limit", "unknown")
            reset_at = rate_limit.get("resetAt", "unknown")
            logger.debug(
                f"Rate limit: {remaining}/{limit} remaining, resets at {reset_at}"
            )
