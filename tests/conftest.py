"""
Pytest configuration and shared fixtures for tests.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def sample_advisory():
    """Sample GitHub advisory response."""
    return {
        "ghsaId": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Test vulnerability",
        "description": "This is a test vulnerability description",
        "severity": "HIGH",
        "publishedAt": "2024-01-01T12:00:00Z",
        "updatedAt": "2024-01-02T12:00:00Z",
        "withdrawnAt": None,
        "permalink": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        "identifiers": [
            {"type": "CVE", "value": "CVE-2024-1234"},
            {"type": "GHSA", "value": "GHSA-xxxx-yyyy-zzzz"},
        ],
        "references": [
            {"url": "https://example.com/advisory"},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
        ],
        "vulnerabilities": {
            "nodes": [
                {
                    "package": {
                        "name": "test-package",
                        "ecosystem": "npm",
                    },
                    "vulnerableVersionRange": "<1.0.0",
                    "firstPatchedVersion": {
                        "identifier": "1.0.0",
                    },
                },
            ],
        },
        "cvss": {
            "score": 7.5,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
    }


@pytest.fixture
def sample_kev_response():
    """Sample CISA KEV catalog response."""
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "product": "test-product",
                "vendorProject": "test-vendor",
                "vulnerabilityName": "Test Vulnerability",
                "dateAdded": "2024-01-01",
                "shortDescription": "Test CVE description",
                "requiredAction": "Apply patches",
                "dueDate": "2024-02-01",
            },
            {
                "cveID": "CVE-2024-5678",
                "product": "another-product",
                "vendorProject": "another-vendor",
                "vulnerabilityName": "Another Vulnerability",
                "dateAdded": "2024-01-02",
                "shortDescription": "Another CVE description",
                "requiredAction": "Mitigation",
                "dueDate": "2024-02-02",
            },
        ],
    }


@pytest.fixture
def sample_csv_row():
    """Sample CSV row."""
    return {
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "cve_ids": "CVE-2024-1234",
        "summary": "Test vulnerability",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "package_name": "test-package",
        "ecosystem": "npm",
        "vulnerable_version_range": "<1.0.0",
        "first_patched_version": "1.0.0",
        "published_at": "2024-01-01T12:00:00Z",
        "updated_at": "2024-01-02T12:00:00Z",
        "references": "https://example.com/advisory",
        "permalink": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        "KEV": "1",
    }


@pytest.fixture
def temp_output_dir(tmp_path):
    """Temporary output directory for tests."""
    return tmp_path / "output"


@pytest.fixture
def mock_config(temp_output_dir):
    """Mock configuration for testing."""
    from github_advisory_downloader.config import Config
    
    return Config(
        github_token="test-token",
        output_dir=temp_output_dir,
        batch_size=100,
        dry_run=False,
        debug=False,
    )


@pytest.fixture
def mock_github_response():
    """Mock GitHub GraphQL API response."""
    return {
        "data": {
            "securityAdvisories": {
                "pageInfo": {
                    "hasNextPage": False,
                    "endCursor": "cursor",
                },
                "nodes": [
                    {
                        "ghsaId": "GHSA-xxxx-yyyy-zzzz",
                        "summary": "Test vulnerability",
                        "severity": "HIGH",
                        "publishedAt": "2024-01-01T12:00:00Z",
                        "updatedAt": "2024-01-02T12:00:00Z",
                        "withdrawnAt": None,
                        "permalink": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
                        "identifiers": [
                            {"type": "CVE", "value": "CVE-2024-1234"},
                        ],
                        "references": [
                            {"url": "https://example.com"},
                        ],
                        "vulnerabilities": {
                            "nodes": [
                                {
                                    "package": {
                                        "name": "test-package",
                                        "ecosystem": "npm",
                                    },
                                    "vulnerableVersionRange": "<1.0.0",
                                    "firstPatchedVersion": {
                                        "identifier": "1.0.0",
                                    },
                                },
                            ],
                        },
                        "cvss": {
                            "score": 7.5,
                            "vectorString": "CVSS:3.1/AV:N/AC:L",
                        },
                    },
                ],
            },
        },
    }
