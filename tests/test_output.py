"""
Unit tests for output module.
"""

import csv
import json
from pathlib import Path

import pytest
from github_advisory_downloader.output import OutputGenerator
from github_advisory_downloader.config import Config


class TestOutputGenerator:
    """Test output generation functions."""

    def test_generator_initialization(self, mock_config):
        """Test output generator initialization."""
        generator = OutputGenerator(mock_config)
        assert generator.config == mock_config
        assert generator.output_dir == Path(mock_config.output_dir)

    def test_generate_csv(self, mock_config, sample_csv_row, temp_output_dir):
        """Test CSV file generation."""
        temp_output_dir.mkdir(parents=True, exist_ok=True)
        generator = OutputGenerator(mock_config)

        rows = [sample_csv_row]
        csv_file = generator.generate_csv(rows, filename="test.csv")

        assert csv_file is not None
        assert csv_file.exists()
        assert csv_file.name == "test.csv"

        # Verify CSV content
        with open(csv_file, "r") as f:
            reader = csv.DictReader(f)
            rows_read = list(reader)
            assert len(rows_read) == 1
            assert rows_read[0]["ghsa_id"] == "GHSA-xxxx-yyyy-zzzz"

    def test_generate_csv_empty(self, mock_config, temp_output_dir):
        """Test CSV generation with empty data."""
        temp_output_dir.mkdir(parents=True, exist_ok=True)
        generator = OutputGenerator(mock_config)

        csv_file = generator.generate_csv([], filename="empty.csv")
        assert csv_file is None

    def test_generate_jsonlines(self, mock_config, sample_csv_row, temp_output_dir):
        """Test JSONL file generation."""
        temp_output_dir.mkdir(parents=True, exist_ok=True)
        generator = OutputGenerator(mock_config)

        rows = [sample_csv_row]
        jsonl_file = generator.generate_jsonlines(rows, filename="test.jsonl")

        assert jsonl_file is not None
        assert jsonl_file.exists()

        # Verify JSONL content
        with open(jsonl_file, "r") as f:
            lines = f.readlines()
            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["ghsa_id"] == "GHSA-xxxx-yyyy-zzzz"

    def test_generate_json_by_severity(self, mock_config, sample_advisory, temp_output_dir):
        """Test JSON file generation by severity."""
        temp_output_dir.mkdir(parents=True, exist_ok=True)
        generator = OutputGenerator(mock_config)

        advisories_by_severity = {
            "CRITICAL": [sample_advisory],
            "HIGH": [],
            "MODERATE": [],
            "LOW": [],
        }

        files = generator.generate_json_by_severity(advisories_by_severity)

        # Should only create file for CRITICAL
        assert len(files) == 1
        assert files[0].exists()
        assert "critical" in files[0].name

    def test_generate_summary(self, mock_config, temp_output_dir):
        """Test summary report generation."""
        temp_output_dir.mkdir(parents=True, exist_ok=True)
        generator = OutputGenerator(mock_config)

        stats = {
            "total_advisories": 100,
            "total_vulnerabilities": 150,
            "kev_matches": 10,
            "validation_errors": 0,
        }
        severity_counts = {
            "CRITICAL": 20,
            "HIGH": 30,
            "MODERATE": 40,
            "LOW": 10,
        }
        ecosystem_counts = {
            "npm": 50,
            "PyPI": 40,
            "Maven": 30,
        }

        summary_file = generator.generate_summary(stats, severity_counts, ecosystem_counts)

        assert summary_file is not None
        assert summary_file.exists()

        # Verify summary content
        with open(summary_file, "r") as f:
            content = f.read()
            assert "Total Advisories" in content
            assert "100" in content
            assert "CRITICAL" in content

    def test_dry_run_mode(self, temp_output_dir, sample_csv_row):
        """Test dry run mode."""
        temp_output_dir.mkdir(parents=True, exist_ok=True)
        config = Config(
            output_dir=temp_output_dir,
            dry_run=True,
        )
        generator = OutputGenerator(config)

        created_files = generator.generate_all(
            rows=[sample_csv_row],
            advisories_by_severity={"HIGH": []},
            stats={"total_advisories": 1, "total_vulnerabilities": 1, "kev_matches": 0},
        )

        assert created_files == {}
