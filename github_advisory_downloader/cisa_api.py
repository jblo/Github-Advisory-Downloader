"""
CISA KEV Catalog API module with caching support.
"""

import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Set

import requests

from .config import Config
from .exceptions import CISAError
from .validation import DataValidator

logger = logging.getLogger(__name__)


class CISAKEVClient:
    """Client for CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, config: Config):
        """
        Initialize CISA KEV client.

        Args:
            config: Configuration instance
        """
        self.config = config
        self.cve_ids: Set[str] = set()
        self._last_fetched: Optional[datetime] = None

    def get_kev_cves(self, force_refresh: bool = False) -> Set[str]:
        """
        Get set of CVEs from CISA KEV catalog with caching.

        Args:
            force_refresh: Force refresh from API even if cached

        Returns:
            Set of CVE IDs

        Raises:
            CISAError: If fetch fails
        """
        # Check cache first
        cached_cves = self._load_cache() if not force_refresh else None
        if cached_cves is not None:
            logger.debug(f"Loaded {len(cached_cves)} CVEs from cache")
            self.cve_ids = cached_cves
            return cached_cves

        # Fetch from API
        logger.info("🔍 Fetching CISA Known Exploited Vulnerabilities catalog...")
        cves = self._fetch_from_api()
        self.cve_ids = cves

        # Save to cache
        self._save_cache(cves)

        return cves

    def _fetch_from_api(self) -> Set[str]:
        """
        Fetch CVEs from CISA KEV API.

        Returns:
            Set of CVE IDs

        Raises:
            CISAError: If fetch fails
        """
        max_retries = self.config.max_retries
        retry_delay = self.config.retry_delay

        for attempt in range(max_retries):
            try:
                response = requests.get(
                    self.config.cisa_kev_url,
                    timeout=self.config.cisa_timeout,
                    headers={"User-Agent": self.config.user_agent},
                )
                response.raise_for_status()

                kev_data = response.json()
                DataValidator.validate_kev_response(kev_data)

                vulnerabilities = kev_data.get("vulnerabilities", [])
                cve_ids = {
                    vuln.get("cveID") for vuln in vulnerabilities if vuln.get("cveID")
                }

                logger.info(f"✅ Loaded {len(cve_ids)} CVEs from CISA KEV catalog")
                self._last_fetched = datetime.now()
                return cve_ids

            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    logger.warning(
                        f"⚠️  Attempt {attempt + 1}/{max_retries} failed: {e}. "
                        f"Retrying in {retry_delay}s..."
                    )
                    time.sleep(retry_delay)
                else:
                    raise CISAError(
                        f"Failed to fetch CISA KEV catalog after {max_retries} attempts: {e}"
                    ) from e

            except Exception as e:
                raise CISAError(f"Error processing CISA KEV catalog: {e}") from e

    def _get_cache_path(self) -> Path:
        """
        Get cache file path.

        Returns:
            Path to cache file
        """
        if not self.config.cisa_cache_dir:
            return None

        cache_file = self.config.cisa_cache_dir / "cisa_kev_cache.json"
        return cache_file

    def _is_cache_valid(self) -> bool:
        """
        Check if cache is still valid based on TTL.

        Returns:
            bool: True if cache exists and is fresh
        """
        cache_path = self._get_cache_path()
        if not cache_path or not cache_path.exists():
            return False

        cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        ttl = timedelta(seconds=self.config.cisa_cache_ttl)

        is_valid = cache_age < ttl
        if not is_valid:
            logger.debug(f"Cache expired (age: {cache_age}, TTL: {ttl})")

        return is_valid

    def _load_cache(self) -> Optional[Set[str]]:
        """
        Load CVEs from cache if valid.

        Returns:
            Set of CVE IDs or None if cache invalid/missing
        """
        if not self._is_cache_valid():
            return None

        cache_path = self._get_cache_path()
        if not cache_path:
            return None

        try:
            with open(cache_path, "r") as f:
                data = json.load(f)
                cves = set(data.get("cve_ids", []))
                logger.debug(f"Loaded {len(cves)} CVEs from cache: {cache_path}")
                return cves
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            return None

    def _save_cache(self, cve_ids: Set[str]) -> None:
        """
        Save CVEs to cache.

        Args:
            cve_ids: Set of CVE IDs to cache
        """
        cache_path = self._get_cache_path()
        if not cache_path or self.config.dry_run:
            return

        try:
            data = {
                "cve_ids": sorted(cve_ids),
                "timestamp": datetime.now().isoformat(),
                "count": len(cve_ids),
            }
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_path, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Cached {len(cve_ids)} CVEs to: {cache_path}")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    def is_known_exploited(self, cve_id: str) -> bool:
        """
        Check if CVE is in KEV catalog.

        Args:
            cve_id: CVE identifier

        Returns:
            bool: True if CVE is known exploited
        """
        return cve_id in self.cve_ids

    def is_any_kev(self, cve_ids: list) -> bool:
        """
        Check if any CVE in list is known exploited.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            bool: True if any CVE is known exploited
        """
        return any(cve_id in self.cve_ids for cve_id in cve_ids)

    def clear_cache(self) -> None:
        """Clear cached data."""
        cache_path = self._get_cache_path()
        if cache_path and cache_path.exists():
            cache_path.unlink()
            logger.debug(f"Cleared cache: {cache_path}")
