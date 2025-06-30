.PHONY: help install test clean build examples install-dev install-test build-test publish-test publish

help:
	@echo "Available commands:"
	@echo "  install       Install package in development mode"
	@echo "  install-dev   Install with development dependencies"
	@echo "  install-test  Install from built wheel for testing"
	@echo "  test          Test the CLI functionality"
	@echo "  clean         Clean build artifacts"
	@echo "  build         Build package"
	@echo "  build-test    Build and test installation"
	@echo "  examples      Run example commands"
	@echo "  publish-test  Publish to Test PyPI"
	@echo "  publish       Publish to PyPI"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

install-test:
	pip install dist/pgdn_cve-*.whl

test:
	@echo "Testing CVE download by ID..."
	pgdn-cve download --cve-id CVE-2021-44228
	@echo "\nTesting CVE search..."
	pgdn-cve search --keyword "log4j" --limit 2

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf src/*.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f *.json

build: clean
	python -m build

build-test: build install-test
	@echo "Testing installation..."
	python -c "import pgdn_cve; print('✓ Library import successful')"
	pgdn-cve --help > /dev/null && echo "✓ CLI command working"

examples:
	@echo "=== PGDN CVE Library Examples ==="
	@echo "\n1. Download specific CVE (Log4Shell):"
	pgdn-cve download --cve-id CVE-2021-44228
	
	@echo "\n\n2. Search for Log4j CVEs (limit 3):"
	pgdn-cve search --keyword "log4j" --limit 3
	
	@echo "\n\n3. Download recent CVEs (last 1 day, limit 5):"
	pgdn-cve download --days 1 --limit 5
	
	@echo "\n\n4. Save search results to file:"
	pgdn-cve search --keyword "apache" --limit 5 --output apache_cves.json
	@echo "Results saved to apache_cves.json"

publish-test: build
	twine upload --repository testpypi dist/*

publish: build
	twine upload dist/*