#!/usr/bin/env python3
"""
PGDN CVE CLI - Download and manage CVE data from NVD API.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any

from .cve_downloader import CVEDownloader


def download_command(args) -> Dict[str, Any]:
    """Download CVEs and return as JSON."""
    try:
        with CVEDownloader(timeout=args.timeout) as downloader:
            if args.cve_id:
                # Download specific CVE
                result = downloader.download_cve_by_id(args.cve_id)
                if "error" in result:
                    return result
                return {
                    "status": "success",
                    "total_cves": 1,
                    "cves": [result]
                }
            elif args.all:
                # Download all CVEs
                cves = downloader.download_all_cves(
                    start_date=args.start_date,
                    end_date=args.end_date,
                    batch_size=args.batch_size,
                    delay_between_requests=args.delay
                )
                
                if isinstance(cves, list) and cves and "error" in cves[0]:
                    return cves[0]
                
                result = {
                    "status": "success",
                    "total_cves": len(cves),
                    "download_type": "all_cves",
                    "start_date": args.start_date or "1999-01-01",
                    "end_date": args.end_date or "now",
                    "cves": cves
                }
                
                # Save to file if requested
                if args.output:
                    save_result = downloader.save_cves_to_file(cves, args.output)
                    result["file_saved"] = save_result
                
                return result
            elif args.year:
                # Download all CVEs for a specific year
                cves = downloader.download_all_cves_by_year(
                    year=args.year,
                    batch_size=args.batch_size,
                    delay_between_requests=args.delay
                )
                
                if isinstance(cves, list) and cves and "error" in cves[0]:
                    return cves[0]
                
                result = {
                    "status": "success",
                    "total_cves": len(cves),
                    "download_type": "year_cves",
                    "year": args.year,
                    "cves": cves
                }
                
                # Save to file if requested
                if args.output:
                    save_result = downloader.save_cves_to_file(cves, args.output)
                    result["file_saved"] = save_result
                
                return result
            else:
                # Download recent CVEs
                cves = downloader.download_recent_cves(
                    days_back=args.days,
                    max_results=args.limit
                )
                
                if isinstance(cves, dict) and "error" in cves:
                    return cves
                
                result = {
                    "status": "success",
                    "total_cves": len(cves),
                    "days_back": args.days,
                    "cves": cves
                }
                
                # Save to file if requested
                if args.output:
                    save_result = downloader.save_cves_to_file(cves, args.output)
                    result["file_saved"] = save_result
                
                return result
                
    except Exception as e:
        return {
            "status": "error",
            "error": "Download failed",
            "details": str(e)
        }


def search_command(args) -> Dict[str, Any]:
    """Search CVEs by keyword."""
    try:
        with CVEDownloader(timeout=args.timeout) as downloader:
            cves = downloader.search_cves_by_keyword(
                keyword=args.keyword,
                max_results=args.limit
            )
            
            if cves and isinstance(cves[0], dict) and "error" in cves[0]:
                return cves[0]
            
            result = {
                "status": "success",
                "keyword": args.keyword,
                "total_cves": len(cves),
                "cves": cves
            }
            
            # Save to file if requested
            if args.output:
                with CVEDownloader() as downloader:
                    save_result = downloader.save_cves_to_file(cves, args.output)
                    result["file_saved"] = save_result
            
            return result
            
    except Exception as e:
        return {
            "status": "error",
            "error": "Search failed",
            "details": str(e)
        }


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="PGDN CVE Library - Download and manage CVE data from NVD API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download recent CVEs (last 7 days)
  pgdn-cve download
  
  # Download CVEs from last 30 days
  pgdn-cve download --days 30
  
  # Download specific CVE
  pgdn-cve download --cve-id CVE-2021-44228
  
  # Download all CVEs (use with caution - this will take a long time)
  pgdn-cve download --all --output all_cves.json
  
  # Download all CVEs for a specific year
  pgdn-cve download --year 2023 --output cves_2023.json
  
  # Download all CVEs with custom date range
  pgdn-cve download --all --start-date 2023-01-01 --end-date 2023-12-31 --output cves_2023.json
  
  # Search CVEs by keyword
  pgdn-cve search --keyword "log4j"
  
  # Save results to file
  pgdn-cve download --days 7 --output cves.json
        """
    )
    
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Download command
    download_parser = subparsers.add_parser('download', help='Download CVE data')
    download_parser.add_argument('--days', type=int, default=7, help='Days back to fetch CVEs')
    download_parser.add_argument('--limit', type=int, default=1000, help='Maximum number of CVEs to fetch')
    download_parser.add_argument('--cve-id', help='Download specific CVE by ID (e.g., CVE-2021-44228)')
    download_parser.add_argument('--output', help='Save results to JSON file')
    download_parser.add_argument('--all', action='store_true', help='Download all CVEs (use with caution)')
    download_parser.add_argument('--start-date', help='Start date for downloading all CVEs (YYYY-MM-DD)')
    download_parser.add_argument('--end-date', help='End date for downloading all CVEs (YYYY-MM-DD)')
    download_parser.add_argument('--batch-size', type=int, default=2000, help='Batch size for downloading all CVEs (max 2000)')
    download_parser.add_argument('--delay', type=float, default=0.6, help='Delay between requests in seconds (for rate limiting)')
    download_parser.add_argument('--year', type=int, help='Download all CVEs for a specific year')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search CVEs by keyword')
    search_parser.add_argument('--keyword', required=True, help='Keyword to search for')
    search_parser.add_argument('--limit', type=int, default=100, help='Maximum number of results')
    search_parser.add_argument('--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute command and output JSON
    try:
        if args.command == 'download':
            result = download_command(args)
        elif args.command == 'search':
            result = search_command(args)
        else:
            result = {"error": "Unknown command"}
        
        # Output JSON result
        print(json.dumps(result, indent=2, default=str))
        
        # Exit with error code if there was an error
        if result.get("status") == "error" or "error" in result:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(json.dumps({"error": "Operation cancelled by user"}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({
            "error": "Unexpected error",
            "details": str(e)
        }))
        sys.exit(1)


if __name__ == '__main__':
    main()