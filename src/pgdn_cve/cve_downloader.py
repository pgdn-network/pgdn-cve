"""
CVE Downloader - Simple CVE data fetching and management from NVD API.
"""

import json
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

import httpx


class CVEDownloader:
    """
    Simple CVE downloader that fetches CVE data from NVD API and returns JSON.
    """
    
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, timeout: int = 30):
        """
        Initialize CVE downloader.
        
        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()
    
    def download_recent_cves(self, days_back: int = 7, max_results: int = 1000) -> List[Dict[str, Any]]:
        """
        Download recent CVEs from NVD API.
        
        Args:
            days_back: Number of days back to fetch CVEs
            max_results: Maximum number of results to fetch
            
        Returns:
            List of CVE dictionaries
        """
        try:
            # Calculate date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            # Format dates for NVD API
            start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            params = {
                "startIndex": 0,
                "resultsPerPage": min(max_results, 2000),  # NVD API limit
                "lastModStartDate": start_date_str,
                "lastModEndDate": end_date_str
            }
            
            response = self.client.get(self.NVD_API_BASE, params=params)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            cve_list = []
            for vulnerability in vulnerabilities:
                cve_data = self._parse_cve_data(vulnerability)
                if cve_data:
                    cve_list.append(cve_data)
            
            return cve_list
            
        except Exception as e:
            return {
                "error": f"Failed to download CVEs: {str(e)}",
                "cves": []
            }
    
    def download_cve_by_id(self, cve_id: str) -> Dict[str, Any]:
        """
        Download a specific CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
            
        Returns:
            CVE data dictionary or error
        """
        try:
            params = {
                "cveId": cve_id
            }
            
            response = self.client.get(self.NVD_API_BASE, params=params)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                return {"error": f"CVE {cve_id} not found"}
            
            cve_data = self._parse_cve_data(vulnerabilities[0])
            return cve_data if cve_data else {"error": f"Failed to parse CVE {cve_id}"}
            
        except Exception as e:
            return {"error": f"Failed to download CVE {cve_id}: {str(e)}"}
    
    def search_cves_by_keyword(self, keyword: str, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Search CVEs by keyword.
        
        Args:
            keyword: Keyword to search for
            max_results: Maximum number of results
            
        Returns:
            List of matching CVE dictionaries
        """
        try:
            params = {
                "startIndex": 0,
                "resultsPerPage": min(max_results, 2000),
                "keywordSearch": keyword
            }
            
            response = self.client.get(self.NVD_API_BASE, params=params)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            cve_list = []
            for vulnerability in vulnerabilities:
                cve_data = self._parse_cve_data(vulnerability)
                if cve_data:
                    cve_list.append(cve_data)
            
            return cve_list
            
        except Exception as e:
            return [{"error": f"Failed to search CVEs: {str(e)}"}]
    
    def _parse_cve_data(self, vulnerability: Dict) -> Optional[Dict[str, Any]]:
        """Parse a single CVE vulnerability from NVD API response."""
        try:
            cve = vulnerability.get("cve", {})
            cve_id = cve.get("id", "")
            
            if not cve_id:
                return None
            
            # Published and modified dates
            published_date = None
            last_modified = None
            
            if "published" in cve:
                try:
                    published_date = cve["published"]
                except:
                    pass
            
            if "lastModified" in cve:
                try:
                    last_modified = cve["lastModified"]
                except:
                    pass
            
            # Description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang", "") == "en":
                    description = desc.get("value", "")
                    break
            
            if not description and descriptions:
                description = descriptions[0].get("value", "")
            
            # CVSS metrics
            metrics = cve.get("metrics", {})
            severity = None
            cvss_score = None
            cvss_vector = None
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]  # Take first metric
                    cvss_data = metric.get("cvssData", {})
                    
                    if "baseSeverity" in cvss_data:
                        severity = cvss_data["baseSeverity"]
                    if "baseScore" in cvss_data:
                        cvss_score = cvss_data["baseScore"]
                    if "vectorString" in cvss_data:
                        cvss_vector = cvss_data["vectorString"]
                    break
            
            # References
            references = []
            ref_data = cve.get("references", [])
            for ref in ref_data:
                if "url" in ref:
                    references.append(ref["url"])
            
            return {
                "cve_id": cve_id,
                "published_date": published_date,
                "last_modified": last_modified,
                "source": "NVD",
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "references": references,
                "download_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception:
            return None
    
    def save_cves_to_file(self, cves: List[Dict[str, Any]], filename: str) -> Dict[str, Any]:
        """
        Save CVEs to JSON file.
        
        Args:
            cves: List of CVE dictionaries
            filename: Output filename
            
        Returns:
            Status dictionary
        """
        try:
            output_data = {
                "metadata": {
                    "total_cves": len(cves),
                    "export_timestamp": datetime.utcnow().isoformat(),
                    "source": "NVD API"
                },
                "cves": cves
            }
            
            with open(filename, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
            
            return {
                "status": "success",
                "message": f"Saved {len(cves)} CVEs to {filename}",
                "filename": filename,
                "total_cves": len(cves)
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to save CVEs: {str(e)}"
            }


def download_cves(days_back: int = 7, max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Convenience function to download recent CVEs.
    
    Args:
        days_back: Number of days back to fetch
        max_results: Maximum number of results
        
    Returns:
        List of CVE dictionaries
    """
    with CVEDownloader() as downloader:
        return downloader.download_recent_cves(days_back, max_results)


def search_cves(keyword: str, max_results: int = 100) -> List[Dict[str, Any]]:
    """
    Convenience function to search CVEs by keyword.
    
    Args:
        keyword: Keyword to search for
        max_results: Maximum number of results
        
    Returns:
        List of CVE dictionaries
    """
    with CVEDownloader() as downloader:
        return downloader.search_cves_by_keyword(keyword, max_results)