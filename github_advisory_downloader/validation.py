"""
Data validation utilities for GitHub Advisory Downloader.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from .exceptions import ValidationError

logger = logging.getLogger(__name__)


class DataValidator:
    """Validate API responses and processed data."""

    # CVE pattern: CVE-YYYY-NNNN or CVE-YYYY-NNNNN (and longer)
    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

    # GHSA pattern: GHSA-xxxx-xxxx-xxxx
    GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")

    # CVSS score: 0.0 to 10.0
    CVSS_MIN = 0.0
    CVSS_MAX = 10.0

    # Valid severities
    VALID_SEVERITIES = {"CRITICAL", "HIGH", "MODERATE", "LOW"}

    @staticmethod
    def validate_cve_id(cve_id: str) -> bool:
        """
        Validate CVE ID format.
        
        Args:
            cve_id: CVE identifier to validate
            
        Returns:
            bool: True if valid CVE format
        """
        if not isinstance(cve_id, str):
            return False
        return bool(DataValidator.CVE_PATTERN.fullmatch(cve_id))

    @staticmethod
    def validate_ghsa_id(ghsa_id: str) -> bool:
        """
        Validate GHSA ID format.
        
        Args:
            ghsa_id: GHSA identifier to validate
            
        Returns:
            bool: True if valid GHSA format
        """
        if not isinstance(ghsa_id, str):
            return False
        return bool(DataValidator.GHSA_PATTERN.fullmatch(ghsa_id))

    @staticmethod
    def validate_cvss_score(score: Any) -> bool:
        """
        Validate CVSS score.
        
        Args:
            score: CVSS score to validate
            
        Returns:
            bool: True if valid CVSS score
        """
        try:
            score_float = float(score)
            return DataValidator.CVSS_MIN <= score_float <= DataValidator.CVSS_MAX
        except (ValueError, TypeError):
            return False

    @staticmethod
    def validate_severity(severity: str) -> bool:
        """
        Validate severity level.
        
        Args:
            severity: Severity level to validate
            
        Returns:
            bool: True if valid severity
        """
        return severity in DataValidator.VALID_SEVERITIES

    @staticmethod
    def validate_timestamp(timestamp: str) -> bool:
        """
        Validate ISO 8601 timestamp.
        
        Args:
            timestamp: Timestamp string to validate
            
        Returns:
            bool: True if valid timestamp
        """
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            return True
        except (ValueError, TypeError, AttributeError):
            return False

    @staticmethod
    def validate_advisory_response(advisory: Dict[str, Any]) -> bool:
        """
        Validate GitHub advisory API response structure.
        
        Args:
            advisory: Advisory data from API
            
        Returns:
            bool: True if valid structure
            
        Raises:
            ValidationError: If critical fields are missing
        """
        required_fields = {"ghsaId", "summary", "severity"}
        missing = required_fields - set(advisory.keys())
        if missing:
            raise ValidationError(f"Advisory missing required fields: {missing}")

        # Validate GHSA ID
        ghsa_id = advisory.get("ghsaId", "")
        if not DataValidator.validate_ghsa_id(ghsa_id):
            raise ValidationError(f"Invalid GHSA ID: {ghsa_id}")

        # Validate severity
        severity = advisory.get("severity", "")
        if not DataValidator.validate_severity(severity):
            raise ValidationError(f"Invalid severity: {severity}")

        # Validate timestamps if present
        for timestamp_field in ["publishedAt", "updatedAt"]:
            ts = advisory.get(timestamp_field)
            if ts and not DataValidator.validate_timestamp(ts):
                raise ValidationError(f"Invalid timestamp in {timestamp_field}: {ts}")

        return True

    @staticmethod
    def validate_cvss_response(cvss: Optional[Dict[str, Any]]) -> bool:
        """
        Validate CVSS data structure.
        
        Args:
            cvss: CVSS data from API
            
        Returns:
            bool: True if valid or None
        """
        if cvss is None:
            return True

        if not isinstance(cvss, dict):
            raise ValidationError(f"CVSS must be a dict or None, got {type(cvss)}")

        # Validate score if present
        score = cvss.get("score")
        if score is not None and not DataValidator.validate_cvss_score(score):
            raise ValidationError(f"Invalid CVSS score: {score}")

        return True

    @staticmethod
    def validate_vulnerability_response(vulnerability: Dict[str, Any]) -> bool:
        """
        Validate vulnerability structure within advisory.
        
        Args:
            vulnerability: Vulnerability data
            
        Returns:
            bool: True if valid structure
        """
        if not isinstance(vulnerability, dict):
            raise ValidationError(f"Vulnerability must be a dict, got {type(vulnerability)}")

        # Package info is optional
        package = vulnerability.get("package")
        if package and not isinstance(package, dict):
            raise ValidationError(f"Package must be a dict, got {type(package)}")

        return True

    @staticmethod
    def validate_cve_list(cve_list: List[str]) -> bool:
        """
        Validate list of CVE IDs.
        
        Args:
            cve_list: List of CVE identifiers
            
        Returns:
            bool: True if all are valid CVE format
        """
        if not isinstance(cve_list, list):
            raise ValidationError(f"CVE list must be a list, got {type(cve_list)}")

        invalid = [cve for cve in cve_list if not DataValidator.validate_cve_id(cve)]
        if invalid:
            raise ValidationError(f"Invalid CVE IDs: {invalid}")

        return True

    @staticmethod
    def validate_kev_response(kev_data: Dict[str, Any]) -> bool:
        """
        Validate CISA KEV catalog response structure.
        
        Args:
            kev_data: KEV catalog data
            
        Returns:
            bool: True if valid structure
            
        Raises:
            ValidationError: If structure is invalid
        """
        if not isinstance(kev_data, dict):
            raise ValidationError(f"KEV data must be a dict, got {type(kev_data)}")

        vulnerabilities = kev_data.get("vulnerabilities")
        if vulnerabilities is None:
            raise ValidationError("KEV data missing 'vulnerabilities' field")

        if not isinstance(vulnerabilities, list):
            raise ValidationError(f"Vulnerabilities must be a list, got {type(vulnerabilities)}")

        return True

    @staticmethod
    def validate_csv_row(row: Dict[str, Any]) -> bool:
        """
        Validate CSV row structure.
        
        Args:
            row: CSV row data
            
        Returns:
            bool: True if valid
            
        Raises:
            ValidationError: If validation fails
        """
        required_fields = {
            "ghsa_id", "cve_ids", "summary", "severity", "published_at"
        }
        missing = required_fields - set(row.keys())
        if missing:
            raise ValidationError(f"CSV row missing required fields: {missing}")

        # Validate GHSA ID
        if row.get("ghsa_id") and not DataValidator.validate_ghsa_id(row["ghsa_id"]):
            raise ValidationError(f"Invalid GHSA ID in CSV row: {row['ghsa_id']}")

        # Validate severity
        if row.get("severity") and not DataValidator.validate_severity(row["severity"]):
            raise ValidationError(f"Invalid severity in CSV row: {row['severity']}")

        # Validate CVSS score if present
        cvss_score = row.get("cvss_score")
        if cvss_score and not DataValidator.validate_cvss_score(cvss_score):
            raise ValidationError(f"Invalid CVSS score in CSV row: {cvss_score}")

        return True

    @staticmethod
    def sanitize_string(value: str, max_length: int = 10000) -> str:
        """
        Sanitize string for CSV/JSON output.
        
        Args:
            value: String to sanitize
            max_length: Maximum allowed length
            
        Returns:
            str: Sanitized string
        """
        if not isinstance(value, str):
            return str(value)

        # Remove null bytes
        value = value.replace("\x00", "")

        # Truncate if too long
        if len(value) > max_length:
            logger.warning(f"Truncating string of length {len(value)} to {max_length}")
            value = value[:max_length]

        return value
