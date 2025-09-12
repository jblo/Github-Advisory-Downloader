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
        
        csv_file = output_dir /
