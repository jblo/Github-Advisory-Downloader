#!/usr/bin/env python3
"""
GitHub Security Advisory Database Downloader
Downloads all security advisories from GitHub's Advisory Database and organizes them by severity.
"""

import requests
import json
import zipfile
import os
import time
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Set
import argparse
import sys

class GitHubAdvisoryDownloader:
    def __init__(self, github_token: str = None):
        """
        Initialize the downloader.
        
        Args:
            github_token: Optional GitHub personal access token for higher rate limits
        """
        self.github_token = github_token
        self.base_url = "https://api.github.com/graphql"
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitHub-Advisory-Downloader"
        }
        if github_token:
            self.headers["Authorization"] = f"Bearer {github_token}"
        
        self.advisories_by_severity = {
            "CRITICAL": [],
            "HIGH": [],
            "MODERATE": [],
            "LOW": []
        }
        
        self.kev_cves: Set[str] = set()  # Set of CVEs in CISA KEV catalog
        self.vulnerability_rows: List[Dict] = []  # For CSV generation
        
        self.stats = {
            "total_downloaded": 0,
            "total_vulnerabilities": 0,
            "kev_matches": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0},
            "errors": 0
        }

    def fetch_cisa_kev_catalog(self) -> None:
        """Fetch the CISA Known Exploited Vulnerabilities catalog."""
        print("🔍 Fetching CISA Known Exploited Vulnerabilities catalog...")
        
        try:
            response = requests.get(self.cisa_kev_url, timeout=30)
            response.raise_for_status()
            
            kev_data = response.json()
            vulnerabilities = kev_data.get("vulnerabilities", [])
            
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID")
                if cve_id:
                    self.kev_cves.add(cve_id)
            
            print(f"✅ Loaded {len(self.kev_cves)} CVEs from CISA KEV catalog")
            
        except Exception as e:
            print(f"⚠️  Could not fetch CISA KEV catalog: {e}")
            print("   Continuing without KEV data...")

    def extract_cve_from_identifiers(self, identifiers: List[Dict]) -> List[str]:
        """Extract CVE IDs from advisory identifiers."""
        cves = []
        for identifier in identifiers:
            if identifier.get("type") == "CVE":
                cves.append(identifier.get("value"))
        return [cve for cve in cves if cve]  # Filter out None values

    def get_advisories_query(self, cursor: str = None) -> str:
        """Generate GraphQL query for fetching security advisories."""
        after_clause = f', after: "{cursor}"' if cursor else ""
        
        return f"""
        {{
            securityAdvisories(first: 100{after_clause}) {{
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

    def fetch_advisories(self) -> None:
        """Fetch all security advisories from GitHub's API."""
        print("🔍 Fetching security advisories from GitHub...")
        
        cursor = None
        page = 1
        
        while True:
            print(f"📄 Fetching page {page}...")
            
            query = self.get_advisories_query(cursor)
            
            try:
                response = requests.post(
                    self.base_url,
                    headers=self.headers,
                    json={"query": query},
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                
                if "errors" in data:
                    print(f"❌ GraphQL errors: {data['errors']}")
                    self.stats["errors"] += 1
                    break
                
                advisories_data = data["data"]["securityAdvisories"]
                advisories = advisories_data["nodes"]
                
                # Process advisories from this page
                for advisory in advisories:
                    severity = advisory.get("severity", "LOW")
                    if severity in self.advisories_by_severity:
                        self.advisories_by_severity[severity].append(advisory)
                        self.stats["by_severity"][severity] += 1
                        self.stats["total_downloaded"] += 1
                        
                        # Process vulnerabilities for CSV
                        self.process_advisory_for_csv(advisory)
                
                print(f"✅ Page {page}: {len(advisories)} advisories processed")
                
                # Check if there are more pages
                page_info = advisories_data["pageInfo"]
                if not page_info["hasNextPage"]:
                    break
                
                cursor = page_info["endCursor"]
                page += 1
                
                # Rate limiting - be nice to GitHub's API
                time.sleep(0.5)
                
            except requests.exceptions.RequestException as e:
                print(f"❌ Error fetching page {page}: {e}")
                self.stats["errors"] += 1
                time.sleep(5)  # Wait before retrying
                continue
            except Exception as e:
                print(f"❌ Unexpected error on page {page}: {e}")
                self.stats["errors"] += 1
                break
        
        print(f"\n📊 Download complete! Total advisories: {self.stats['total_downloaded']}")
        print(f"📊 Total vulnerabilities processed: {self.stats['total_vulnerabilities']}")
        print(f"📊 KEV matches found: {self.stats['kev_matches']}")
        for severity, count in self.stats["by_severity"].items():
            print(f"   {severity}: {count}")

    def process_advisory_for_csv(self, advisory: Dict[Any, Any]) -> None:
        """Process an advisory and extract vulnerability data for CSV."""
        ghsa_id = advisory.get("ghsaId", "")
        summary = advisory.get("summary", "")
        description = advisory.get("description", "")
        severity = advisory.get("severity", "")
        published_at = advisory.get("publishedAt", "")
        updated_at = advisory.get("updatedAt", "")
        permalink = advisory.get("permalink", "")
        
        # Extract CVE IDs
        cve_ids = self.extract_cve_from_identifiers(advisory.get("identifiers", []))
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
        
        # Extract references
        references = []
        if advisory.get("references"):
            references = [ref.get("url", "") for ref in advisory["references"]]
        references_list = ", ".join(filter(None, references))
        
        # Process vulnerabilities
        vulnerabilities = advisory.get("vulnerabilities", {})
        if vulnerabilities and "nodes" in vulnerabilities:
            for vuln in vulnerabilities["nodes"]:
                self.stats["total_vulnerabilities"] += 1
                
                # Package information
                package_info = vuln.get("package", {})
                package_name = package_info.get("name", "")
                ecosystem = package_info.get("ecosystem", "")
                
                # Version information
                vulnerable_range = vuln.get("vulnerableVersionRange", "")
                patched_version = ""
                if vuln.get("firstPatchedVersion"):
                    patched_version = vuln["firstPatchedVersion"].get("identifier", "")
                
                # Create CSV row
                row = {
                    "ghsa_id": ghsa_id,
                    "cve_ids": cve_list,
                    "summary": summary,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "vulnerable_version_range": vulnerable_range,
                    "first_patched_version": patched_version,
                    "published_at": published_at,
                    "updated_at": updated_at,
                    "references": references_list,
                    "permalink": permalink,
                    "KEV": "1" if is_kev else ""
                }
                
                self.vulnerability_rows.append(row)
        else:
            # Advisory without specific package vulnerabilities
            self.stats["total_vulnerabilities"] += 1
            
            row = {
                "ghsa_id": ghsa_id,
                "cve_ids": cve_list,
                "summary": summary,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "package_name": "",
                "ecosystem": "",
                "vulnerable_version_range": "",
                "first_patched_version": "",
                "published_at": published_at,
                "updated_at": updated_at,
                "references": references_list,
                "permalink": permalink,
                "KEV": "1" if is_kev else ""
            }
            
            self.vulnerability_rows.append(row)

    def create_csv_file(self, output_dir: Path) -> None:
        """Create CSV file with vulnerability data."""
        print(f"\n📊 Creating CSV file with {len(self.vulnerability_rows)} vulnerability records...")
        
        csv_file = output_dir / f"github_advisories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        if not self.vulnerability_rows:
            print("⚠️  No vulnerability data to write to CSV")
            return
        
        # CSV column headers
        fieldnames = [
            "ghsa_id", "cve_ids", "summary", "severity", "cvss_score", "cvss_vector",
            "package_name", "ecosystem", "vulnerable_version_range", "first_patched_version",
            "published_at", "updated_at", "references", "permalink", "KEV"
        ]
        
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.vulnerability_rows)
            
            print(f"✅ CSV file created: {csv_file}")
            print(f"   Total records: {len(self.vulnerability_rows)}")
            
        except Exception as e:
            print(f"❌ Error creating CSV file: {e}")

    def save_json_files(self, output_dir: Path) -> None:
        """Save advisories organized by severity as separate JSON files."""
        print(f"\n📄 Saving JSON files by severity...")
        
        for severity, advisories in self.advisories_by_severity.items():
            if advisories:  # Only create files for severities that have data
                filename = f"advisories_{severity.lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                filepath = output_dir / filename
                
                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(advisories, f, indent=2, default=str)
                    
                    print(f"✅ {severity}: {len(advisories)} advisories saved to {filename}")
                    
                except Exception as e:
                    print(f"❌ Error saving {severity} advisories: {e}")
        
        # Also save all advisories in a single file
        all_advisories_file = output_dir / f"all_advisories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(all_advisories_file, 'w', encoding='utf-8') as f:
                json.dump(self.advisories_by_severity, f, indent=2, default=str)
            
            print(f"✅ All advisories saved to {all_advisories_file.name}")
            
        except Exception as e:
            print(f"❌ Error saving all advisories file: {e}")

    def download_and_save(self, output_dir: str = "github_advisories_output", 
                         create_csv: bool = True, create_json: bool = True) -> None:
        """Main method to download advisories and save them to files."""
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        print(f"📁 Output directory: {output_path.absolute()}")
        
        # Fetch CISA KEV catalog first
        self.fetch_cisa_kev_catalog()
        
        # Download all advisories
        self.fetch_advisories()
        
        # Save files
        if create_csv:
            self.create_csv_file(output_path)
        
        if create_json:
            self.save_json_files(output_path)
        
        print(f"\n🎉 Download complete!")
        print(f"📊 Final Statistics:")
        print(f"   Total advisories downloaded: {self.stats['total_downloaded']}")
        print(f"   Total vulnerability records: {self.stats['total_vulnerabilities']}")
        print(f"   KEV matches: {self.stats['kev_matches']}")
        print(f"   Errors encountered: {self.stats['errors']}")
        print(f"   Files saved to: {output_path.absolute()}")


def main():
    """Main function to run the GitHub Advisory Downloader."""
    parser = argparse.ArgumentParser(
        description="Download GitHub Security Advisories and organize them by severity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s                           # Download all advisories
  %(prog)s --token YOUR_TOKEN       # Use GitHub token for higher rate limits
  %(prog)s --output my_output       # Save to custom directory
  %(prog)s --no-csv                 # Skip CSV generation
  %(prog)s --no-json                # Skip JSON files
        """
    )
    
    parser.add_argument(
        "--token", "-t",
        help="GitHub personal access token (optional, for higher rate limits)"
    )
    
    parser.add_argument(
        "--output", "-o", 
        default="github_advisories_output",
        help="Output directory (default: github_advisories_output)"
    )
    
    parser.add_argument(
        "--no-csv", 
        action="store_true",
        help="Skip CSV file generation"
    )
    
    parser.add_argument(
        "--no-json", 
        action="store_true",
        help="Skip JSON file generation"
    )
    
    args = parser.parse_args()
    
    print("🚀 GitHub Security Advisory Downloader")
    print("="*50)
    
    # Initialize downloader
    downloader = GitHubAdvisoryDownloader(github_token=args.token)
    
    try:
        # Run the download and save process
        downloader.download_and_save(
            output_dir=args.output,
            create_csv=not args.no_csv,
            create_json=not args.no_json
        )
        
    except KeyboardInterrupt:
        print("\n⚠️  Download interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

