# PGDN CVE Library

A simple Python library for downloading and managing CVE (Common Vulnerabilities and Exposures) data from the NVD (National Vulnerability Database) API.

## Features

- **CVE Download**: Fetch recent CVEs from NVD API
- **CVE Search**: Search CVEs by keyword
- **Specific CVE Lookup**: Download individual CVEs by ID
- **JSON Output**: Clean JSON format for all operations
- **File Export**: Save CVE data to JSON files
- **CLI Interface**: Command-line tool for easy access

## Installation

```bash
pip install pgdn-cve
```

## Quick Start

### Library Usage

```python
from pgdn_cve import CVEDownloader, download_cves, search_cves

# Download recent CVEs (last 7 days)
recent_cves = download_cves(days_back=7, max_results=100)
print(f"Downloaded {len(recent_cves)} CVEs")

# Search CVEs by keyword
log4j_cves = search_cves("log4j", max_results=50)
print(f"Found {len(log4j_cves)} Log4j CVEs")

# Using the CVEDownloader class directly
with CVEDownloader() as downloader:
    # Download specific CVE
    cve_data = downloader.download_cve_by_id("CVE-2021-44228")
    print(f"CVE: {cve_data['cve_id']}")
    print(f"Severity: {cve_data['severity']}")
    
    # Download and save to file
    cves = downloader.download_recent_cves(days_back=30)
    result = downloader.save_cves_to_file(cves, "recent_cves.json")
    print(f"Saved {result['total_cves']} CVEs to file")
```

### CLI Usage

```bash
# Download recent CVEs (last 7 days)
pgdn-cve download

# Download CVEs from last 30 days
pgdn-cve download --days 30

# Download specific CVE
pgdn-cve download --cve-id CVE-2021-44228

# Search CVEs by keyword
pgdn-cve search --keyword "log4j"

# Save results to file
pgdn-cve download --days 7 --output recent_cves.json

# Search and save results
pgdn-cve search --keyword "apache" --limit 50 --output apache_cves.json
```

## Output Format

All functions return CVE data in a standardized JSON format:

### Single CVE Structure
```json
{
  "cve_id": "CVE-2021-44228",
  "published_date": "2021-12-10T10:15:09.817Z",
  "last_modified": "2023-11-07T04:15:31.613Z",
  "source": "NVD",
  "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features...",
  "severity": "CRITICAL",
  "cvss_score": 10.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "references": [
    "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
    "https://www.apache.org/security/advisory.html"
  ],
  "download_timestamp": "2024-01-15T10:30:45.123456"
}
```

### Download Response Structure
```json
{
  "status": "success",
  "total_cves": 150,
  "days_back": 7,
  "cves": [
    {
      "cve_id": "CVE-2024-0001",
      "description": "...",
      "severity": "HIGH",
      ...
    }
  ]
}
```

### Search Response Structure
```json
{
  "status": "success",
  "keyword": "log4j",
  "total_cves": 25,
  "cves": [
    {
      "cve_id": "CVE-2021-44228",
      "description": "...",
      "severity": "CRITICAL",
      ...
    }
  ]
}
```

## Command Line Interface

### Download Command
```bash
pgdn-cve download [options]

Options:
  --days DAYS       Days back to fetch CVEs (default: 7)
  --limit LIMIT     Maximum number of CVEs (default: 1000)
  --cve-id CVE_ID   Download specific CVE by ID
  --output FILE     Save results to JSON file
  --timeout SEC     Request timeout in seconds (default: 30)
```

### Search Command
```bash
pgdn-cve search --keyword KEYWORD [options]

Options:
  --keyword KEYWORD  Keyword to search for (required)
  --limit LIMIT      Maximum number of results (default: 100)
  --output FILE      Save results to JSON file
  --timeout SEC      Request timeout in seconds (default: 30)
```

## Examples

### Download Examples
```bash
# Download CVEs from last week
pgdn-cve download --days 7

# Download specific CVE with full details
pgdn-cve download --cve-id CVE-2021-44228

# Download recent CVEs and save to file
pgdn-cve download --days 30 --limit 500 --output monthly_cves.json
```

### Search Examples
```bash
# Search for Log4j vulnerabilities
pgdn-cve search --keyword "log4j"

# Search for Apache vulnerabilities
pgdn-cve search --keyword "apache" --limit 100

# Search and save results
pgdn-cve search --keyword "nginx" --output nginx_cves.json
```

## API Rate Limiting

The NVD API has rate limits. This library:
- Respects API rate limits with appropriate delays
- Uses reasonable default timeouts (30 seconds)
- Handles API errors gracefully
- Returns error information in JSON format

## Error Handling

All functions return JSON responses with error information:

```json
{
  "status": "error",
  "error": "Download failed",
  "details": "Connection timeout after 30 seconds"
}
```

## Development

### Setup Development Environment
```bash
git clone https://github.com/pgdn-network/pgdn-cve.git
cd pgdn-cve
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

### Run Tests
```bash
pytest
```

### Code Formatting
```bash
black src/ tests/
isort src/ tests/
flake8 src/ tests/
```

## Dependencies

- **httpx**: HTTP client for API requests
- **Python 3.8+**: Minimum Python version

## Data Source

This library fetches data from the official [NVD API](https://nvd.nist.gov/developers/vulnerabilities):
- **API Version**: 2.0
- **Data Source**: NIST National Vulnerability Database
- **Update Frequency**: Real-time from NVD
- **Data Format**: JSON

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

- **Issues**: [GitHub Issues](https://github.com/pgdn-network/pgdn-cve/issues)
- **Documentation**: This README
- **Security**: For security issues, email security@pgdn.network