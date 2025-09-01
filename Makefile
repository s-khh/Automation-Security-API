.PHONY: help setup install test security-test critical-test owasp-test auth-test injection-test ci-test ci-security ci-critical validate-workflows check-ci lint format clean report
help:
	@echo "Bosta API Security Testing Framework"
	@echo ""
	@echo "Available commands:"
	@echo "  setup           - Set up the development environment"
	@echo "  install         - Install dependencies"
	@echo "  test            - Run all tests"
	@echo "  security-test   - Run security tests only"
	@echo "  critical-test   - Run critical security tests only"
	@echo "  owasp-test      - Run OWASP Top 10 tests"
	@echo "  auth-test       - Run authentication tests"
	@echo "  injection-test  - Run injection attack tests"
	@echo ""
	@echo "CI/CD commands:"
	@echo "  ci-test         - Run tests for CI/CD"
	@echo "  ci-security     - Run security tests for CI/CD"
	@echo "  ci-critical     - Run critical tests for CI/CD"
	@echo "  validate-workflows - Validate GitHub Actions workflows"
	@echo "  check-ci        - Check CI/CD status"
	@echo ""
	@echo "Development commands:"
	@echo "  lint            - Run code linting"
	@echo "  format          - Format code"
	@echo "  clean           - Clean up generated files"
	@echo "  report          - (Disabled) Security reporting"
setup:
	@echo "Setting up development environment..."
	python -m venv venv
	@echo "Virtual environment created. Activate with:"
	@echo "  source venv/bin/activate  (Linux/Mac)"
	@echo "  venv\\Scripts\\activate     (Windows)"
install:
	@echo "Installing dependencies..."
	pip install --upgrade pip
	pip install -r requirements.txt
	@echo "Dependencies installed successfully!"
test:
	@echo "Running all tests..."
	mkdir -p reports
	python3 -m pytest tests/ -v \
		--html=reports/test-report.html \
		--self-contained-html \
		--junitxml=reports/junit.xml
security-test:
	@echo "Running security tests..."
	mkdir -p reports
	python3 -m pytest tests/ -m "security" -v \
		--html=reports/security-report.html \
		--self-contained-html \
		--junitxml=reports/security-junit.xml
critical-test:
	@echo "Running critical security tests..."
	mkdir -p reports
	python3 -m pytest tests/ -m "critical" -v \
		--html=reports/critical-report.html \
		--self-contained-html \
		--junitxml=reports/critical-junit.xml
owasp-test:
	@echo "Running OWASP Top 10 tests..."
	mkdir -p reports
	python3 -m pytest tests/ -m "owasp" -v \
		--html=reports/owasp-report.html \
		--self-contained-html \
		--junitxml=reports/owasp-junit.xml
auth-test:
	@echo "Running authentication tests..."
	mkdir -p reports
	python3 -m pytest tests/ -m "auth" -v \
		--html=reports/auth-report.html \
		--self-contained-html \
		--junitxml=reports/auth-junit.xml
injection-test:
	@echo "Running injection tests..."
	mkdir -p reports
	python3 -m pytest tests/ -m "injection" -v \
		--html=reports/injection-report.html \
		--self-contained-html \
		--junitxml=reports/injection-junit.xml
ci-test:
	@echo " Running tests for CI/CD..."
	python3 -m pytest tests/ -v --tb=short --maxfail=5
ci-security:
	@echo " Running security tests for CI/CD..."
	python3 -m pytest tests/ -m "security" -v --tb=short
ci-critical:
	@echo " Running critical security tests for CI/CD..."
	python3 -m pytest tests/ -m "critical" -v --tb=short --maxfail=3
validate-workflows:
	@echo " Validating GitHub Actions workflows..."
	@for file in .github/workflows/*.yml; do \
		echo "Checking $$file..."; \
		python3 -c "import yaml; yaml.safe_load(open('$$file'))" && echo " $$file is valid" || echo " $$file has errors"; \
	done
check-ci:
	@echo " Checking CI/CD status..."
	@if [ -d .git ]; then \
		echo "Git repository detected"; \
		echo "GitHub Actions workflows:"; \
		ls -la .github/workflows/; \
	else \
		echo "Not a git repository - initialize with 'git init' to use CI/CD"; \
	fi
lint:
	@echo "Running code linting..."
	flake8 core/ tests/ --max-line-length=120 --ignore=E203,W503
	mypy core/ --ignore-missing-imports
format:
	@echo "Formatting code..."
	black core/ tests/ --line-length=120
	isort core/ tests/
clean:
	@echo "Cleaning up..."
	rm -rf reports/
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	rm -rf core/__pycache__/
	rm -rf tests/__pycache__/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -f security_report_*.json
	rm -f security_report_*.html
report:
	@echo "   Security reporting has been disabled per user request"
	@echo "   Run 'make test' or 'make security-test' to see test results directly"
