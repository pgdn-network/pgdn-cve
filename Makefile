.PHONY: help install test clean build examples

help:
	@echo "Available commands:"
	@echo "  install     Install package in development mode"
	@echo "  test        Test the CLI functionality"
	@echo "  clean       Clean build artifacts"
	@echo "  build       Build package"
	@echo "  examples    Run example commands"

install:
	pip install -e .

test:
	@echo "Testing CVE download by ID..."
	python pgdn_cve_cli.py download --cve-id CVE-2021-44228
	@echo "\nTesting CVE search..."
	python pgdn_cve_cli.py search --keyword "log4j" --limit 2

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f *.json

build: clean
	python -m build

examples:
	@echo "=== PGDN CVE Library Examples ==="
	@echo "\n1. Download specific CVE (Log4Shell):"
	python pgdn_cve_cli.py download --cve-id CVE-2021-44228
	
	@echo "\n\n2. Search for Log4j CVEs (limit 3):"
	python pgdn_cve_cli.py search --keyword "log4j" --limit 3
	
	@echo "\n\n3. Download recent CVEs (last 1 day, limit 5):"
	python pgdn_cve_cli.py download --days 1 --limit 5
	
	@echo "\n\n4. Save search results to file:"
	python pgdn_cve_cli.py search --keyword "apache" --limit 5 --output apache_cves.json
	@echo "Results saved to apache_cves.json"