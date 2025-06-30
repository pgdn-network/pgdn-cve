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

### From PyPI (Recommended)

```bash
pip install pgdn-cve
```

### From Source

```bash
# Clone the repository
git clone https://github.com/pgdn-network/pgdn-cve.git
cd pgdn-cve

# Install in development mode
pip install -e .
```

### Development Installation

```bash
# Clone the repository
git clone https://github.com/pgdn-network/pgdn-cve.git
cd pgdn-cve

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install with development dependencies
pip install -e ".[dev]"
```

### Building from Source

```bash
# Install build tools
pip install build

# Build the package
python -m build

# Install the built package
pip install dist/pgdn_cve-*.whl
```

### Verification

After installation, verify the package works:

```bash
# Test library import
python -c "import pgdn_cve; print('Installation successful!')"

# Test CLI
pgdn-cve --help
```

## Using as a Library

The PGDN CVE Library can be used as a Python package in your applications:

### Basic Import

```python
from pgdn_cve import CVEDownloader, download_cves, search_cves, iter_cves
```

### Available Functions

- `download_cves(days_back=7, max_results=1000, timeout=30)`: Download recent CVEs
- `search_cves(keyword, max_results=100, timeout=30)`: Search CVEs by keyword
- `CVEDownloader`: Class for more advanced usage
- `iter_cves(start_date=None, end_date=None, batch_size=1000)`: Efficiently iterate over all CVEs in batches (for incremental sync)

### Simple Examples

```python
import json
from pgdn_cve import download_cves, search_cves

# Download recent CVEs
recent_cves = download_cves(days_back=7, max_results=50)
print(f"Downloaded {len(recent_cves['cves'])} CVEs")

# Search for specific vulnerabilities
log4j_cves = search_cves("log4j", max_results=20)
print(f"Found {len(log4j_cves['cves'])} Log4j CVEs")

# Access individual CVE data
for cve in recent_cves['cves']:
    print(f"{cve['cve_id']}: {cve['severity']} - {cve['description'][:100]}...")
```

### Incremental Batch Fetching Example (Efficient Sync)

If you want to fetch only new CVEs since your last pull, use the `iter_cves` function. This is ideal for production sync jobs:

```python
from pgdn_cve import iter_cves

# Load this from your database or a state file
last_pull = load_last_pull_timestamp()  # e.g., "2024-06-28T00:00:00"

for batch in iter_cves(start_date=last_pull, batch_size=1000):
    # Process or save this batch
    save_to_db(batch)
    # Update last_pull to the latest published_date in this batch
    last_pull = max(
        (cve['published_date'] for cve in batch if cve.get('published_date')),
        default=last_pull
    )
    save_last_pull_timestamp(last_pull)
```

- This approach avoids re-downloading old data and is robust for incremental updates.
- You control the batch size and the date window.
- The library handles pagination and rate limiting for you.

### Advanced Usage with CVEDownloader Class

```python
from pgdn_cve import CVEDownloader

# Using context manager (recommended)
with CVEDownloader() as downloader:
    # Download specific CVE
    cve_data = downloader.download_cve_by_id("CVE-2021-44228")
    print(f"CVE: {cve_data['cve_id']}")
    print(f"Severity: {cve_data['severity']}")
    
    # Download and save to file
    cves = downloader.download_recent_cves(days_back=30)
    result = downloader.save_cves_to_file(cves, "recent_cves.json")
    print(f"Saved {result['total_cves']} CVEs to file")

# Manual instantiation
downloader = CVEDownloader()
try:
    cves = downloader.download_recent_cves(days_back=7)
    print(f"Downloaded {len(cves['cves'])} CVEs")
finally:
    downloader.close()
```

### Integration Examples

#### Flask Web Application

```python
from flask import Flask, jsonify, request
from pgdn_cve import search_cves, download_cves

app = Flask(__name__)

@app.route('/api/cves/recent')
def get_recent_cves():
    days = request.args.get('days', 7, type=int)
    limit = request.args.get('limit', 100, type=int)
    
    try:
        result = download_cves(days_back=days, max_results=limit)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cves/search')
def search_cve():
    keyword = request.args.get('keyword')
    if not keyword:
        return jsonify({'error': 'Keyword required'}), 400
    
    try:
        result = search_cves(keyword)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
```

#### Django Management Command

```python
# management/commands/update_cves.py
from django.core.management.base import BaseCommand
from pgdn_cve import download_cves
from myapp.models import CVE

class Command(BaseCommand):
    help = 'Update CVE database from NVD'

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, default=7)
        parser.add_argument('--limit', type=int, default=1000)

    def handle(self, *args, **options):
        try:
            result = download_cves(
                days_back=options['days'],
                max_results=options['limit']
            )
            
            for cve_data in result['cves']:
                CVE.objects.update_or_create(
                    cve_id=cve_data['cve_id'],
                    defaults={
                        'description': cve_data['description'],
                        'severity': cve_data['severity'],
                        'cvss_score': cve_data['cvss_score'],
                    }
                )
            
            self.stdout.write(
                self.style.SUCCESS(f"Updated {len(result['cves'])} CVEs")
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Error updating CVEs: {e}")
            )
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

### Package Distribution

#### Building for Distribution

```bash
# Install build tools
pip install build twine

# Build source and wheel distributions
python -m build

# Check the built package
twine check dist/*
```

#### Publishing to PyPI

```bash
# Upload to Test PyPI first (recommended)
twine upload --repository testpypi dist/*

# Upload to PyPI
twine upload dist/*
```

#### Local Installation Testing

```bash
# Install from built wheel
pip install dist/pgdn_cve-*.whl

# Test the installation
python -c "import pgdn_cve; print('Success!')"
pgdn-cve --help
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

## Troubleshooting

### Common Installation Issues

#### Permission Errors
If you encounter permission errors during installation:
```bash
# Use --user flag for user installation
pip install --user pgdn-cve

# Or use a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install pgdn-cve
```

#### Import Errors
If you get import errors after installation:
```bash
# Verify installation
pip list | grep pgdn-cve

# Check Python path
python -c "import sys; print(sys.path)"

# Reinstall if needed
pip uninstall pgdn-cve
pip install pgdn-cve
```

#### CLI Command Not Found
If the `pgdn-cve` command is not found:
```bash
# Check if entry point is installed
pip show pgdn-cve

# Try running with python -m
python -m pgdn_cve.cli --help

# Reinstall with --force-reinstall
pip install --force-reinstall pgdn-cve
```

#### Build Errors
If you encounter build errors:
```bash
# Update build tools
pip install --upgrade build setuptools wheel

# Clean and rebuild
make clean
make build
```

### API Rate Limiting
If you encounter API rate limiting errors:
- Reduce the number of concurrent requests
- Increase delays between requests
- Use smaller `max_results` values
- Consider implementing caching for repeated queries

### Network Issues
If you have network connectivity issues:
- Check your internet connection
- Verify firewall settings
- Try using a different network
- Check if the NVD API is accessible: https://services.nvd.nist.gov/rest/json/cves/2.0

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