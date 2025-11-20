"""
Output generation module for various export formats.
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .config import Config
from .exceptions import DataProcessingError

logger = logging.getLogger(__name__)


class OutputGenerator:
    """Generate output files in various formats."""

    def __init__(self, config: Config):
        """
        Initialize output generator.

        Args:
            config: Configuration instance
        """
        self.config = config
        self.output_dir = Path(config.output_dir)

    def generate_csv(self, rows: List[Dict[str, Any]], filename: str = None) -> Path:
        """
        Generate CSV file from vulnerability rows.

        Args:
            rows: List of vulnerability data dicts
            filename: Optional custom filename

        Returns:
            Path to created CSV file

        Raises:
            DataProcessingError: If file generation fails
        """
        if not rows:
            logger.warning("⚠️  No data to write to CSV")
            return None

        if filename is None:
            timestamp = (
                datetime.now().strftime("%Y%m%d_%H%M%S")
                if self.config.timestamp_outputs
                else ""
            )
            filename = (
                f"vulnerabilities_{timestamp}.csv"
                if timestamp
                else "vulnerabilities.csv"
            )

        csv_file = self.output_dir / filename

        logger.info(f"📊 Creating CSV file with {len(rows)} records...")

        fieldnames = [
            "ghsa_id",
            "cve_ids",
            "summary",
            "severity",
            "cvss_score",
            "cvss_vector",
            "package_name",
            "ecosystem",
            "vulnerable_version_range",
            "first_patched_version",
            "published_at",
            "updated_at",
            "references",
            "permalink",
            "KEV",
        ]

        try:
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            logger.info(f"✅ CSV file created: {csv_file}")
            return csv_file

        except Exception as e:
            raise DataProcessingError(f"Failed to create CSV file: {e}") from e

    def generate_json_by_severity(self, advisories: Dict[str, List[Any]]) -> List[Path]:
        """
        Generate JSON files organized by severity.

        Args:
            advisories: Dict mapping severity to list of advisories

        Returns:
            List of created file paths

        Raises:
            DataProcessingError: If file generation fails
        """
        logger.info("📄 Saving JSON files by severity...")
        created_files = []

        for severity, advisory_list in advisories.items():
            if not advisory_list:
                continue

            timestamp = (
                datetime.now().strftime("%Y%m%d_%H%M%S")
                if self.config.timestamp_outputs
                else ""
            )
            filename = (
                f"advisories_{severity.lower()}_{timestamp}.json"
                if timestamp
                else f"advisories_{severity.lower()}.json"
            )
            filepath = self.output_dir / filename

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(advisory_list, f, indent=2, default=str)

                logger.info(
                    f"✅ {severity}: {len(advisory_list)} advisories → {filename}"
                )
                created_files.append(filepath)

            except Exception as e:
                logger.error(f"❌ Failed to save {severity} JSON: {e}")
                raise DataProcessingError(
                    f"Failed to create {severity} JSON: {e}"
                ) from e

        return created_files

    def generate_jsonlines(
        self, rows: List[Dict[str, Any]], filename: str = None
    ) -> Path:
        """
        Generate JSONL (JSON Lines) file for streaming analysis.

        Args:
            rows: List of vulnerability data dicts
            filename: Optional custom filename

        Returns:
            Path to created file

        Raises:
            DataProcessingError: If file generation fails
        """
        if not rows:
            logger.warning("⚠️  No data to write to JSONL")
            return None

        if filename is None:
            timestamp = (
                datetime.now().strftime("%Y%m%d_%H%M%S")
                if self.config.timestamp_outputs
                else ""
            )
            filename = (
                f"vulnerabilities_{timestamp}.jsonl"
                if timestamp
                else "vulnerabilities.jsonl"
            )

        jsonl_file = self.output_dir / filename

        logger.info(f"📄 Creating JSONL file with {len(rows)} records...")

        try:
            with open(jsonl_file, "w", encoding="utf-8") as f:
                for row in rows:
                    f.write(json.dumps(row, default=str) + "\n")

            logger.info(f"✅ JSONL file created: {jsonl_file}")
            return jsonl_file

        except Exception as e:
            raise DataProcessingError(f"Failed to create JSONL file: {e}") from e

    def generate_summary(
        self,
        stats: Dict[str, Any],
        severity_counts: Dict[str, int] = None,
        ecosystem_counts: Dict[str, int] = None,
    ) -> Path:
        """
        Generate summary report.

        Args:
            stats: Statistics dict
            severity_counts: Dict with severity level counts
            ecosystem_counts: Dict with ecosystem counts

        Returns:
            Path to created summary file

        Raises:
            DataProcessingError: If file generation fails
        """
        timestamp = (
            datetime.now().strftime("%Y%m%d_%H%M%S")
            if self.config.timestamp_outputs
            else ""
        )
        filename = (
            f"download_summary_{timestamp}.txt" if timestamp else "download_summary.txt"
        )
        summary_file = self.output_dir / filename

        logger.info("📋 Creating summary report...")

        try:
            with open(summary_file, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n")
                f.write("GitHub Security Advisory Downloader - Summary Report\n")
                f.write("=" * 60 + "\n\n")

                f.write(f"Generated: {datetime.now().isoformat()}\n\n")

                # Statistics
                f.write("STATISTICS\n")
                f.write("-" * 60 + "\n")
                f.write(
                    f"Total Advisories Downloaded: {stats.get('total_advisories', 0)}\n"
                )
                f.write(
                    f"Total Vulnerability Records: {stats.get('total_vulnerabilities', 0)}\n"
                )
                f.write(
                    f"Known Exploited Vulnerabilities (KEV): {stats.get('kev_matches', 0)}\n"
                )
                f.write(f"Validation Errors: {stats.get('validation_errors', 0)}\n\n")

                # Severity breakdown
                if severity_counts:
                    f.write("SEVERITY BREAKDOWN\n")
                    f.write("-" * 60 + "\n")
                    for severity in ["CRITICAL", "HIGH", "MODERATE", "LOW"]:
                        count = severity_counts.get(severity, 0)
                        f.write(f"{severity:12}: {count:6} advisories\n")
                    f.write("\n")

                # Ecosystem breakdown
                if ecosystem_counts:
                    f.write("TOP AFFECTED ECOSYSTEMS (Top 10)\n")
                    f.write("-" * 60 + "\n")
                    sorted_ecosystems = sorted(
                        ecosystem_counts.items(), key=lambda x: x[1], reverse=True
                    )[:10]
                    for ecosystem, count in sorted_ecosystems:
                        f.write(f"{ecosystem:20}: {count:6} vulnerabilities\n")
                    f.write("\n")

                f.write("=" * 60 + "\n")
                f.write("Report completed successfully.\n")

            logger.info(f"✅ Summary report created: {summary_file}")
            return summary_file

        except Exception as e:
            raise DataProcessingError(f"Failed to create summary: {e}") from e

    def generate_all(
        self,
        rows: List[Dict[str, Any]],
        advisories_by_severity: Dict[str, List[Any]],
        stats: Dict[str, Any],
        severity_counts: Dict[str, int] = None,
        ecosystem_counts: Dict[str, int] = None,
    ) -> Dict[str, Path]:
        """
        Generate all configured output formats.

        Args:
            rows: CSV rows
            advisories_by_severity: Advisories grouped by severity
            stats: Statistics
            severity_counts: Severity breakdown
            ecosystem_counts: Ecosystem breakdown

        Returns:
            Dict mapping format name to file path
        """
        if self.config.dry_run:
            logger.info("🏜️  DRY RUN: Skipping file generation")
            return {}

        created_files = {}

        # CSV
        if "csv" in self.config.output_formats:
            try:
                csv_path = self.generate_csv(rows)
                if csv_path:
                    created_files["csv"] = csv_path
            except Exception as e:
                logger.error(f"Failed to generate CSV: {e}")

        # JSON by severity
        if "json" in self.config.output_formats:
            try:
                json_files = self.generate_json_by_severity(advisories_by_severity)
                created_files["json"] = json_files
            except Exception as e:
                logger.error(f"Failed to generate JSON: {e}")

        # JSON Lines
        if "jsonl" in self.config.output_formats:
            try:
                jsonl_path = self.generate_jsonlines(rows)
                if jsonl_path:
                    created_files["jsonl"] = jsonl_path
            except Exception as e:
                logger.error(f"Failed to generate JSONL: {e}")

        # Summary report
        if self.config.create_summary:
            try:
                summary_path = self.generate_summary(
                    stats, severity_counts, ecosystem_counts
                )
                created_files["summary"] = summary_path
            except Exception as e:
                logger.error(f"Failed to generate summary: {e}")

        return created_files
