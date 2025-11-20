"""
Data processing and transformation module.
"""

import logging
from typing import Any, Dict, List, Set

from .exceptions import DataProcessingError
from .validation import DataValidator

logger = logging.getLogger(__name__)


class AdvisoryProcessor:
    """Process advisory data from GitHub API."""

    def __init__(self, kev_cves: Set[str]):
        """
        Initialize advisory processor.

        Args:
            kev_cves: Set of CVEs from CISA KEV catalog
        """
        self.kev_cves = kev_cves
        self.vulnerability_rows: List[Dict[str, Any]] = []
        self.stats = {
            "total_advisories": 0,
            "total_vulnerabilities": 0,
            "kev_matches": 0,
            "validation_errors": 0,
        }

    def process_advisory(self, advisory: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process advisory and extract vulnerability rows for CSV.

        Args:
            advisory: Advisory data from GitHub API

        Returns:
            List of CSV rows for this advisory

        Raises:
            DataProcessingError: If processing fails
        """
        try:
            self.stats["total_advisories"] += 1

            # Extract common fields
            ghsa_id = advisory.get("ghsaId", "")
            summary = advisory.get("summary", "")
            description = advisory.get("description", "")
            severity = advisory.get("severity", "")
            published_at = advisory.get("publishedAt", "")
            updated_at = advisory.get("updatedAt", "")
            permalink = advisory.get("permalink", "")

            # Extract CVE IDs
            cve_ids = self._extract_cve_ids(advisory.get("identifiers", []))
            cve_list = ", ".join(cve_ids) if cve_ids else ""

            # Check if any CVE is in KEV catalog
            is_kev = any(cve in self.kev_cves for cve in cve_ids)
            if is_kev:
                self.stats["kev_matches"] += 1

            # Extract CVSS information
            cvss_score = ""
            cvss_vector = ""
            if advisory.get("cvss"):
                cvss_score = advisory["cvss"].get("score", "")
                cvss_vector = advisory["cvss"].get("vectorString", "")

                # Validate CVSS
                if cvss_score and not DataValidator.validate_cvss_score(cvss_score):
                    logger.warning(f"Invalid CVSS score for {ghsa_id}: {cvss_score}")
                    cvss_score = ""

            # Extract references
            references = []
            if advisory.get("references"):
                references = [
                    ref.get("url", "")
                    for ref in advisory["references"]
                    if ref.get("url")
                ]
            references_list = ", ".join(filter(None, references))

            # Process vulnerabilities
            rows = self._process_vulnerabilities(
                advisory,
                ghsa_id,
                cve_list,
                summary,
                severity,
                cvss_score,
                cvss_vector,
                published_at,
                updated_at,
                references_list,
                permalink,
                is_kev,
            )

            return rows

        except Exception as e:
            self.stats["validation_errors"] += 1
            raise DataProcessingError(
                f"Failed to process advisory {advisory.get('ghsaId', 'unknown')}: {e}"
            ) from e

    def _extract_cve_ids(self, identifiers: List[Dict[str, Any]]) -> List[str]:
        """
        Extract CVE IDs from advisory identifiers.

        Args:
            identifiers: List of identifier dicts

        Returns:
            List of CVE IDs
        """
        cves = []
        for identifier in identifiers:
            if identifier.get("type") == "CVE":
                cve_id = identifier.get("value")
                if cve_id and DataValidator.validate_cve_id(cve_id):
                    cves.append(cve_id)
        return cves

    def _process_vulnerabilities(
        self,
        advisory: Dict[str, Any],
        ghsa_id: str,
        cve_list: str,
        summary: str,
        severity: str,
        cvss_score: Any,
        cvss_vector: str,
        published_at: str,
        updated_at: str,
        references_list: str,
        permalink: str,
        is_kev: bool,
    ) -> List[Dict[str, Any]]:
        """
        Process vulnerabilities within an advisory.

        Args:
            advisory: Full advisory data
            ghsa_id: GHSA ID
            cve_list: Comma-separated CVE IDs
            summary: Advisory summary
            severity: Severity level
            cvss_score: CVSS score
            cvss_vector: CVSS vector string
            published_at: Publication timestamp
            updated_at: Update timestamp
            references_list: Comma-separated references
            permalink: GitHub advisory URL
            is_kev: Whether advisory is in KEV catalog

        Returns:
            List of CSV rows
        """
        rows = []
        vulnerabilities = advisory.get("vulnerabilities", {})

        if vulnerabilities and "nodes" in vulnerabilities:
            vuln_nodes = vulnerabilities["nodes"]
            if vuln_nodes:
                for vuln in vuln_nodes:
                    try:
                        DataValidator.validate_vulnerability_response(vuln)
                        self.stats["total_vulnerabilities"] += 1

                        # Package information
                        package_info = vuln.get("package", {})
                        package_name = package_info.get("name", "")
                        ecosystem = package_info.get("ecosystem", "")

                        # Version information
                        vulnerable_range = vuln.get("vulnerableVersionRange", "")
                        patched_version = ""
                        if vuln.get("firstPatchedVersion"):
                            patched_version = vuln["firstPatchedVersion"].get(
                                "identifier", ""
                            )

                        row = {
                            "ghsa_id": DataValidator.sanitize_string(ghsa_id),
                            "cve_ids": DataValidator.sanitize_string(cve_list),
                            "summary": DataValidator.sanitize_string(summary),
                            "severity": severity,
                            "cvss_score": cvss_score,
                            "cvss_vector": DataValidator.sanitize_string(cvss_vector),
                            "package_name": DataValidator.sanitize_string(package_name),
                            "ecosystem": ecosystem,
                            "vulnerable_version_range": DataValidator.sanitize_string(
                                vulnerable_range
                            ),
                            "first_patched_version": DataValidator.sanitize_string(
                                patched_version
                            ),
                            "published_at": published_at,
                            "updated_at": updated_at,
                            "references": references_list,
                            "permalink": DataValidator.sanitize_string(permalink),
                            "KEV": "1" if is_kev else "",
                        }

                        # Validate row
                        try:
                            DataValidator.validate_csv_row(row)
                            rows.append(row)
                        except Exception as e:
                            logger.warning(f"Invalid CSV row for {ghsa_id}: {e}")

                    except Exception as e:
                        logger.warning(
                            f"Failed to process vulnerability in {ghsa_id}: {e}"
                        )
                        continue
            else:
                # No vulnerability nodes - create generic row
                rows.append(
                    self._create_generic_row(
                        ghsa_id,
                        cve_list,
                        summary,
                        severity,
                        cvss_score,
                        cvss_vector,
                        published_at,
                        updated_at,
                        references_list,
                        permalink,
                        is_kev,
                    )
                )
        else:
            # No vulnerabilities section - create generic row
            rows.append(
                self._create_generic_row(
                    ghsa_id,
                    cve_list,
                    summary,
                    severity,
                    cvss_score,
                    cvss_vector,
                    published_at,
                    updated_at,
                    references_list,
                    permalink,
                    is_kev,
                )
            )
            self.stats["total_vulnerabilities"] += 1

        return rows

    def _create_generic_row(
        self,
        ghsa_id: str,
        cve_list: str,
        summary: str,
        severity: str,
        cvss_score: Any,
        cvss_vector: str,
        published_at: str,
        updated_at: str,
        references_list: str,
        permalink: str,
        is_kev: bool,
    ) -> Dict[str, Any]:
        """
        Create a generic CSV row for advisory without specific vulnerabilities.

        Returns:
            CSV row dict
        """
        return {
            "ghsa_id": DataValidator.sanitize_string(ghsa_id),
            "cve_ids": DataValidator.sanitize_string(cve_list),
            "summary": DataValidator.sanitize_string(summary),
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": DataValidator.sanitize_string(cvss_vector),
            "package_name": "",
            "ecosystem": "",
            "vulnerable_version_range": "",
            "first_patched_version": "",
            "published_at": published_at,
            "updated_at": updated_at,
            "references": references_list,
            "permalink": DataValidator.sanitize_string(permalink),
            "KEV": "1" if is_kev else "",
        }

    def add_rows(self, rows: List[Dict[str, Any]]) -> None:
        """
        Add rows to internal storage.

        Args:
            rows: List of CSV rows
        """
        self.vulnerability_rows.extend(rows)

    def get_rows(self) -> List[Dict[str, Any]]:
        """
        Get all processed rows.

        Returns:
            List of CSV rows
        """
        return self.vulnerability_rows

    def get_stats(self) -> Dict[str, Any]:
        """
        Get processing statistics.

        Returns:
            Dict with statistics
        """
        return self.stats.copy()
