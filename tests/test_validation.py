"""
Unit tests for validation module.
"""

import pytest

from github_advisory_downloader.exceptions import ValidationError
from github_advisory_downloader.validation import DataValidator


class TestDataValidator:
    """Test data validation functions."""

    def test_validate_cve_id_valid(self):
        """Test valid CVE ID validation."""
        assert DataValidator.validate_cve_id("CVE-2024-1234")
        assert DataValidator.validate_cve_id("CVE-2024-12345")
        assert DataValidator.validate_cve_id("CVE-2024-123456")

    def test_validate_cve_id_invalid(self):
        """Test invalid CVE ID validation."""
        assert not DataValidator.validate_cve_id("CVE-24-1234")
        assert not DataValidator.validate_cve_id("CVE-2024-123")
        assert not DataValidator.validate_cve_id("INVALID-2024-1234")
        assert not DataValidator.validate_cve_id(None)
        assert not DataValidator.validate_cve_id(123)

    def test_validate_ghsa_id_valid(self):
        """Test valid GHSA ID validation."""
        assert DataValidator.validate_ghsa_id("GHSA-abcd-efgh-ijkl")
        assert DataValidator.validate_ghsa_id("GHSA-0000-0000-0000")

    def test_validate_ghsa_id_invalid(self):
        """Test invalid GHSA ID validation."""
        assert not DataValidator.validate_ghsa_id("GHSA-abcd-efgh")
        assert not DataValidator.validate_ghsa_id("INVALID-abcd-efgh-ijkl")
        assert not DataValidator.validate_ghsa_id(None)

    def test_validate_cvss_score_valid(self):
        """Test valid CVSS score validation."""
        assert DataValidator.validate_cvss_score(0.0)
        assert DataValidator.validate_cvss_score(5.0)
        assert DataValidator.validate_cvss_score(10.0)
        assert DataValidator.validate_cvss_score("7.5")
        assert DataValidator.validate_cvss_score(7.5)

    def test_validate_cvss_score_invalid(self):
        """Test invalid CVSS score validation."""
        assert not DataValidator.validate_cvss_score(-1.0)
        assert not DataValidator.validate_cvss_score(11.0)
        assert not DataValidator.validate_cvss_score("invalid")
        assert not DataValidator.validate_cvss_score(None)

    def test_validate_severity_valid(self):
        """Test valid severity validation."""
        assert DataValidator.validate_severity("CRITICAL")
        assert DataValidator.validate_severity("HIGH")
        assert DataValidator.validate_severity("MODERATE")
        assert DataValidator.validate_severity("LOW")

    def test_validate_severity_invalid(self):
        """Test invalid severity validation."""
        assert not DataValidator.validate_severity("UNKNOWN")
        assert not DataValidator.validate_severity("critical")
        assert not DataValidator.validate_severity(None)

    def test_validate_timestamp_valid(self):
        """Test valid timestamp validation."""
        assert DataValidator.validate_timestamp("2024-01-01T12:00:00Z")
        assert DataValidator.validate_timestamp("2024-01-01T12:00:00+00:00")
        assert DataValidator.validate_timestamp("2024-01-01T12:00:00.000Z")

    def test_validate_timestamp_invalid(self):
        """Test invalid timestamp validation."""
        assert not DataValidator.validate_timestamp("2024-01-01")
        assert not DataValidator.validate_timestamp("invalid")
        assert not DataValidator.validate_timestamp(None)

    def test_validate_advisory_response_valid(self, sample_advisory):
        """Test valid advisory response validation."""
        assert DataValidator.validate_advisory_response(sample_advisory)

    def test_validate_advisory_response_missing_fields(self):
        """Test advisory response with missing required fields."""
        advisory = {
            "ghsaId": "GHSA-xxxx-yyyy-zzzz",
            # Missing summary and severity
        }
        with pytest.raises(ValidationError):
            DataValidator.validate_advisory_response(advisory)

    def test_validate_advisory_response_invalid_ghsa_id(self):
        """Test advisory response with invalid GHSA ID."""
        advisory = {
            "ghsaId": "INVALID-ID",
            "summary": "Test",
            "severity": "HIGH",
        }
        with pytest.raises(ValidationError):
            DataValidator.validate_advisory_response(advisory)

    def test_validate_kev_response_valid(self, sample_kev_response):
        """Test valid KEV response validation."""
        assert DataValidator.validate_kev_response(sample_kev_response)

    def test_validate_kev_response_invalid(self):
        """Test invalid KEV response validation."""
        with pytest.raises(ValidationError):
            DataValidator.validate_kev_response({})

        with pytest.raises(ValidationError):
            DataValidator.validate_kev_response({"vulnerabilities": "invalid"})

    def test_validate_csv_row_valid(self, sample_csv_row):
        """Test valid CSV row validation."""
        assert DataValidator.validate_csv_row(sample_csv_row)

    def test_validate_csv_row_missing_fields(self):
        """Test CSV row with missing required fields."""
        row = {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            # Missing other required fields
        }
        with pytest.raises(ValidationError):
            DataValidator.validate_csv_row(row)

    def test_sanitize_string(self):
        """Test string sanitization."""
        # Normal string
        assert DataValidator.sanitize_string("test") == "test"

        # String with null bytes
        assert DataValidator.sanitize_string("test\x00string") == "teststring"

        # Long string
        long_str = "a" * 15000
        sanitized = DataValidator.sanitize_string(long_str, max_length=10000)
        assert len(sanitized) == 10000

        # Non-string
        assert DataValidator.sanitize_string(123) == "123"
