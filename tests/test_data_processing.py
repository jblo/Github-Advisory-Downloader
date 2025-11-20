"""
Unit tests for data processing module.
"""

import pytest
from github_advisory_downloader.data_processing import AdvisoryProcessor


class TestAdvisoryProcessor:
    """Test advisory processing functions."""

    def test_processor_initialization(self):
        """Test processor initialization."""
        kev_cves = {"CVE-2024-1234", "CVE-2024-5678"}
        processor = AdvisoryProcessor(kev_cves)

        assert processor.kev_cves == kev_cves
        assert len(processor.vulnerability_rows) == 0
        stats = processor.get_stats()
        assert stats["total_advisories"] == 0

    def test_process_advisory_valid(self, sample_advisory):
        """Test processing a valid advisory."""
        kev_cves = {"CVE-2024-1234"}
        processor = AdvisoryProcessor(kev_cves)

        rows = processor.process_advisory(sample_advisory)

        assert len(rows) > 0
        assert rows[0]["ghsa_id"] == "GHSA-xxxx-yyyy-zzzz"
        assert rows[0]["severity"] == "HIGH"
        assert rows[0]["KEV"] == "1"  # Should be marked as KEV

    def test_process_advisory_not_kev(self, sample_advisory):
        """Test processing an advisory not in KEV."""
        kev_cves = {"CVE-2024-9999"}  # Different CVE
        processor = AdvisoryProcessor(kev_cves)

        rows = processor.process_advisory(sample_advisory)

        assert len(rows) > 0
        assert rows[0]["KEV"] == ""  # Should not be marked as KEV

    def test_extract_cve_ids(self, sample_advisory):
        """Test CVE ID extraction."""
        processor = AdvisoryProcessor(set())
        cve_ids = processor._extract_cve_ids(sample_advisory["identifiers"])

        assert "CVE-2024-1234" in cve_ids
        assert "GHSA-xxxx-yyyy-zzzz" not in cve_ids

    def test_add_rows_and_get_rows(self, sample_csv_row):
        """Test adding and retrieving rows."""
        processor = AdvisoryProcessor(set())

        rows = [sample_csv_row]
        processor.add_rows(rows)

        retrieved_rows = processor.get_rows()
        assert len(retrieved_rows) == 1
        assert retrieved_rows[0]["ghsa_id"] == sample_csv_row["ghsa_id"]

    def test_get_stats(self, sample_advisory):
        """Test statistics tracking."""
        kev_cves = {"CVE-2024-1234"}
        processor = AdvisoryProcessor(kev_cves)

        processor.process_advisory(sample_advisory)

        stats = processor.get_stats()
        assert stats["total_advisories"] == 1
        assert stats["total_vulnerabilities"] >= 1
        assert stats["kev_matches"] == 1

    def test_process_advisory_with_multiple_vulnerabilities(self):
        """Test processing advisory with multiple vulnerabilities."""
        advisory = {
            "ghsaId": "GHSA-test-test-test",
            "summary": "Test",
            "severity": "HIGH",
            "publishedAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z",
            "permalink": "https://github.com/advisories/test",
            "identifiers": [{"type": "CVE", "value": "CVE-2024-1234"}],
            "references": [],
            "vulnerabilities": {
                "nodes": [
                    {
                        "package": {"name": "pkg1", "ecosystem": "npm"},
                        "vulnerableVersionRange": "<1.0.0",
                        "firstPatchedVersion": {"identifier": "1.0.0"},
                    },
                    {
                        "package": {"name": "pkg2", "ecosystem": "npm"},
                        "vulnerableVersionRange": "<2.0.0",
                        "firstPatchedVersion": {"identifier": "2.0.0"},
                    },
                ]
            },
            "cvss": {"score": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L"},
        }

        processor = AdvisoryProcessor(set())
        rows = processor.process_advisory(advisory)

        # Should have one row per package
        assert len(rows) == 2
        assert rows[0]["package_name"] == "pkg1"
        assert rows[1]["package_name"] == "pkg2"
