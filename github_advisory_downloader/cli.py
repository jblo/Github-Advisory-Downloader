"""
Command-line interface for GitHub Advisory Downloader.
"""

import argparse
import logging
import sys
from collections import defaultdict
from pathlib import Path

try:
    from rich.console import Console
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from . import (AdvisoryProcessor, CISAKEVClient, Config, GitHubAdvisoryClient,
               OutputGenerator)
from .exceptions import (CISAError, ConfigurationError,
                         GitHubAdvisoryDownloaderException, GitHubAPIError)


def setup_logging(debug: bool = False) -> logging.Logger:
    """
    Setup logging configuration.

    Args:
        debug: Enable debug logging

    Returns:
        Logger instance
    """
    log_level = logging.DEBUG if debug else logging.INFO

    # Create logger
    logger = logging.getLogger("github_advisory_downloader")
    logger.setLevel(log_level)

    # Remove existing handlers
    logger.handlers = []

    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure argument parser.

    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog="github-advisory-downloader",
        description="Download GitHub Security Advisories and organize them by severity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s                                # Download all advisories
  %(prog)s --token YOUR_TOKEN             # Use GitHub token for higher rate limits
  %(prog)s --output my_output             # Save to custom directory
  %(prog)s --filter CRITICAL HIGH         # Filter by severity
  %(prog)s --dry-run                      # Preview without writing files
  %(prog)s --debug                        # Enable debug logging
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0",
    )

    parser.add_argument(
        "--token",
        "-t",
        help="GitHub personal access token (optional, recommended for higher rate limits)",
    )

    parser.add_argument(
        "--output",
        "-o",
        default="github_advisories_output",
        help="Output directory (default: github_advisories_output)",
    )

    parser.add_argument(
        "--format",
        "-f",
        nargs="+",
        default=["csv", "json"],
        choices=["csv", "json", "jsonl"],
        help="Output formats (default: csv json)",
    )

    parser.add_argument(
        "--filter",
        nargs="+",
        default=None,
        choices=["CRITICAL", "HIGH", "MODERATE", "LOW"],
        help="Filter advisories by severity",
    )

    parser.add_argument(
        "--batch-size",
        "-b",
        type=int,
        default=100,
        help="GraphQL batch size (default: 100, max: 100)",
    )

    parser.add_argument(
        "--cache-dir",
        help="Directory for caching KEV catalog (default: .cache)",
    )

    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Skip summary report generation",
    )

    parser.add_argument(
        "--timestamp",
        action="store_true",
        default=True,
        help="Add timestamps to output files (default: enabled)",
    )

    parser.add_argument(
        "--no-timestamp",
        dest="timestamp",
        action="store_false",
        help="Disable timestamps in output filenames",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview run without writing files",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    return parser


def main():
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(debug=args.debug)
    logger.info("🚀 GitHub Security Advisory Downloader v2.0.0")
    logger.info("=" * 60)

    try:
        # Parse arguments
        severity_filter = set(args.filter) if args.filter else None
        output_formats = set(args.format)

        # Create configuration
        config = Config.from_env_and_args(
            github_token=args.token,
            output_dir=Path(args.output),
            output_formats=output_formats,
            batch_size=args.batch_size,
            severity_filter=severity_filter,
            create_summary=not args.no_summary,
            timestamp_outputs=args.timestamp,
            dry_run=args.dry_run,
            debug=args.debug,
            cisa_cache_dir=Path(args.cache_dir) if args.cache_dir else None,
        )

        logger.info(f"Configuration: {config}")

        # Fetch CISA KEV catalog
        logger.info("\n📥 Fetching data...")
        cisa_client = CISAKEVClient(config)
        kev_cves = cisa_client.get_kev_cves()

        # Initialize GitHub client and fetch advisories
        github_client = GitHubAdvisoryClient(config)
        logger.info(f"📊 GitHub API batch size: {config.batch_size}")
        github_client.log_rate_limit()

        # Initialize processor
        processor = AdvisoryProcessor(kev_cves)

        # Collect data
        advisories_by_severity = defaultdict(list)
        advisory_count = 0

        try:
            if RICH_AVAILABLE:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                ) as progress:
                    task = progress.add_task("Fetching advisories...", total=None)

                    for advisory in github_client.get_advisories(
                        severity_filter=severity_filter,
                    ):
                        # Process advisory
                        rows = processor.process_advisory(advisory)
                        processor.add_rows(rows)

                        # Organize by severity
                        severity = advisory.get("severity", "LOW")
                        advisories_by_severity[severity].append(advisory)

                        advisory_count += 1
                        if advisory_count % 100 == 0:
                            progress.update(
                                task,
                                description=f"📥 Fetched {advisory_count} advisories",
                            )

                    progress.update(
                        task, description=f"✅ Fetched {advisory_count} advisories"
                    )
            else:
                for i, advisory in enumerate(
                    github_client.get_advisories(
                        severity_filter=severity_filter,
                    )
                ):
                    rows = processor.process_advisory(advisory)
                    processor.add_rows(rows)

                    severity = advisory.get("severity", "LOW")
                    advisories_by_severity[severity].append(advisory)

                    advisory_count += 1
                    if advisory_count % 100 == 0:
                        logger.info(f"📥 Fetched {advisory_count} advisories...")

        except (GitHubAPIError, CISAError) as e:
            logger.error(f"❌ API Error: {e}")
            return 1

        logger.info(f"✅ Downloaded {advisory_count} advisories")

        # Generate output
        logger.info("\n💾 Generating output...")
        stats = processor.get_stats()
        rows = processor.get_rows()

        # Calculate breakdowns
        severity_counts = {}
        ecosystem_counts = defaultdict(int)

        for row in rows:
            severity = row.get("severity", "LOW")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            ecosystem = row.get("ecosystem")
            if ecosystem:
                ecosystem_counts[ecosystem] += 1

        # Generate files
        output_gen = OutputGenerator(config)
        created_files = output_gen.generate_all(
            rows=rows,
            advisories_by_severity=dict(advisories_by_severity),
            stats=stats,
            severity_counts=severity_counts,
            ecosystem_counts=dict(ecosystem_counts),
        )

        # Print summary
        logger.info("\n" + "=" * 60)
        logger.info("📊 FINAL STATISTICS")
        logger.info("=" * 60)
        logger.info(f"Total advisories: {stats['total_advisories']}")
        logger.info(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
        logger.info(f"Known exploited (KEV): {stats['kev_matches']}")
        logger.info(f"Validation errors: {stats['validation_errors']}")
        logger.info("")
        logger.info("SEVERITY BREAKDOWN:")
        for severity in ["CRITICAL", "HIGH", "MODERATE", "LOW"]:
            count = severity_counts.get(severity, 0)
            logger.info(f"  {severity:10}: {count:6} advisories")

        if created_files:
            logger.info("")
            logger.info("FILES GENERATED:")
            for format_name, paths in created_files.items():
                if isinstance(paths, list):
                    for path in paths:
                        logger.info(f"  ✅ {format_name.upper()}: {path}")
                else:
                    logger.info(f"  ✅ {format_name.upper()}: {paths}")

        if args.dry_run:
            logger.info("\n🏜️  DRY RUN: No files were written")

        logger.info("=" * 60)
        logger.info("🎉 Download complete!")

        return 0

    except ConfigurationError as e:
        logger.error(f"❌ Configuration Error: {e}")
        return 1
    except GitHubAdvisoryDownloaderException as e:
        logger.error(f"❌ Error: {e}")
        return 1
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Download interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"❌ Unexpected Error: {e}", exc_info=args.debug)
        return 1


if __name__ == "__main__":
    sys.exit(main())
