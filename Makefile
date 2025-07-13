# VoiceFlow Comprehensive Testing Framework Makefile

.PHONY: help test test-unit test-integration test-e2e test-performance test-security test-comprehensive
.PHONY: test-docker test-local test-ci clean setup install-deps
.PHONY: report analytics baseline docker-build docker-test
.PHONY: lint format check-security quality-gates

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
PIP := pip3
TEST_RESULTS_DIR := test_results
DOCKER_IMAGE := voiceflow-test-runner
TEST_CONFIG := test_config.yaml

# Help target
help: ## Show this help message
	@echo "VoiceFlow Comprehensive Testing Framework"
	@echo "========================================"
	@echo
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo
	@echo "Examples:"
	@echo "  make test-unit          # Run unit tests only"
	@echo "  make test-comprehensive # Run all tests"
	@echo "  make test-docker        # Run tests in Docker"
	@echo "  make report            # Generate analytics report"

# Setup and installation
setup: ## Set up the testing environment
	@echo "Setting up VoiceFlow testing environment..."
	$(PYTHON) -m venv venv
	. venv/bin/activate && $(PIP) install --upgrade pip
	. venv/bin/activate && $(PIP) install -r requirements_testing.txt
	mkdir -p $(TEST_RESULTS_DIR)
	@echo "Setup complete!"

install-deps: ## Install testing dependencies
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements_testing.txt
	$(PIP) install pytest-xdist pytest-html pytest-cov
	$(PIP) install psutil matplotlib seaborn pandas numpy

# Local testing targets
test-unit: ## Run unit tests
	@echo "Running unit tests..."
	$(PYTHON) test_orchestrator.py --types unit --parallel --output-dir $(TEST_RESULTS_DIR)

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	$(PYTHON) test_orchestrator.py --types integration --output-dir $(TEST_RESULTS_DIR)

test-e2e: ## Run end-to-end tests
	@echo "Running end-to-end tests..."
	$(PYTHON) comprehensive_test_suite.py

test-performance: ## Run performance tests
	@echo "Running performance tests..."
	$(PYTHON) performance_regression_tests.py

test-security: ## Run security tests
	@echo "Running security tests..."
	$(PYTHON) run_security_tests.py

test-comprehensive: ## Run comprehensive test suite
	@echo "Running comprehensive test suite..."
	$(PYTHON) test_orchestrator.py --config $(TEST_CONFIG) --output-dir $(TEST_RESULTS_DIR)

test-quick: ## Run quick smoke tests
	@echo "Running quick smoke tests..."
	$(PYTHON) test_orchestrator.py --types unit --tags smoke --output-dir $(TEST_RESULTS_DIR)

# Test categories
test-core: ## Test core functionality
	@echo "Testing core functionality..."
	$(PYTHON) test_orchestrator.py --types unit integration --tags core --output-dir $(TEST_RESULTS_DIR)

test-ai: ## Test AI enhancement features
	@echo "Testing AI enhancement..."
	$(PYTHON) test_orchestrator.py --types unit integration --tags ai --output-dir $(TEST_RESULTS_DIR)

test-audio: ## Test audio processing
	@echo "Testing audio processing..."
	$(PYTHON) test_orchestrator.py --types unit integration --tags audio --output-dir $(TEST_RESULTS_DIR)

# Docker testing
docker-build: ## Build test Docker image
	@echo "Building test Docker image..."
	docker build -f docker/test-runner.Dockerfile -t $(DOCKER_IMAGE) .

docker-test: docker-build ## Run tests in Docker
	@echo "Running tests in Docker..."
	docker-compose -f docker-compose.testing.yml up --build --abort-on-container-exit

docker-test-unit: docker-build ## Run unit tests in Docker
	docker run --rm -v $(PWD)/$(TEST_RESULTS_DIR):/app/test_results $(DOCKER_IMAGE) unit

docker-test-integration: docker-build ## Run integration tests in Docker
	docker run --rm -v $(PWD)/$(TEST_RESULTS_DIR):/app/test_results $(DOCKER_IMAGE) integration

docker-test-e2e: docker-build ## Run E2E tests in Docker
	docker run --rm -v $(PWD)/$(TEST_RESULTS_DIR):/app/test_results -e ENABLE_XVFB=true $(DOCKER_IMAGE) e2e

# Parallel testing
test-parallel: ## Run tests in parallel using Docker Compose
	@echo "Running tests in parallel..."
	docker-compose -f docker-compose.testing.yml up --build unit-tests integration-tests e2e-tests --abort-on-container-exit

# Load testing (resource intensive)
test-load: ## Run load tests
	@echo "Running load tests (this may take a while)..."
	docker-compose -f docker-compose.testing.yml --profile load-testing up load-tests --abort-on-container-exit

# CI/CD targets
test-ci: ## Run tests for CI/CD pipeline
	@echo "Running CI/CD test suite..."
	$(PYTHON) test_orchestrator.py --config $(TEST_CONFIG) --fail-fast --output-dir $(TEST_RESULTS_DIR)

quality-gates: ## Check quality gates
	@echo "Checking quality gates..."
	$(PYTHON) -c "
import json
import glob
import sys

# Load latest test results
report_files = glob.glob('$(TEST_RESULTS_DIR)/test_results_*.json')
if not report_files:
    print('No test results found')
    sys.exit(1)

with open(sorted(report_files)[-1]) as f:
    results = json.load(f)

# Check quality gates
min_success_rate = 95
if results['success_rate'] < min_success_rate:
    print(f'Quality gate FAILED: Success rate {results[\"success_rate\"]:.2f}% < {min_success_rate}%')
    sys.exit(1)

print(f'Quality gates PASSED: Success rate {results[\"success_rate\"]:.2f}%')
"

# Reporting and analytics
report: ## Generate test analytics report
	@echo "Generating test analytics report..."
	$(PYTHON) test_analytics.py --generate-report --days 30

analytics: ## Run test analytics and generate insights
	@echo "Running test analytics..."
	$(PYTHON) test_analytics.py --import-results $(TEST_RESULTS_DIR) --generate-report --days 30

baseline: ## Update performance baseline
	@echo "Updating performance baseline..."
	$(PYTHON) performance_regression_tests.py --update-baseline

trend-analysis: ## Analyze test trends
	@echo "Analyzing test trends..."
	$(PYTHON) test_analytics.py --trend-analysis --days 90

# Code quality
lint: ## Run code linting
	@echo "Running code linting..."
	flake8 --config .flake8 .
	pylint --rcfile .pylintrc core/ utils/ tests/

format: ## Format code
	@echo "Formatting code..."
	black --config pyproject.toml .
	isort --settings-path pyproject.toml .

check-security: ## Run security checks
	@echo "Running security checks..."
	bandit -r . -f json -o security-report.json
	safety check --json --output safety-report.json

type-check: ## Run type checking
	@echo "Running type checks..."
	mypy --config-file mypy.ini core/ utils/

# Maintenance
clean: ## Clean up test artifacts
	@echo "Cleaning up test artifacts..."
	rm -rf $(TEST_RESULTS_DIR)/*
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name "*~" -delete

clean-docker: ## Clean up Docker resources
	@echo "Cleaning up Docker resources..."
	docker-compose -f docker-compose.testing.yml down --volumes --remove-orphans
	docker image prune -f
	docker volume prune -f

reset: clean ## Reset testing environment
	@echo "Resetting testing environment..."
	rm -f performance_baseline.json
	rm -f test_analytics.db

# Development helpers
watch: ## Watch for changes and run quick tests
	@echo "Watching for changes..."
	while inotifywait -r -e modify,create,delete --exclude="\.git|__pycache__|\.pyc" .; do \
		make test-quick; \
	done

debug: ## Run tests with debugging enabled
	@echo "Running tests with debugging..."
	$(PYTHON) test_orchestrator.py --types unit --pdb --output-dir $(TEST_RESULTS_DIR)

profile: ## Profile test performance
	@echo "Profiling test performance..."
	$(PYTHON) -m cProfile -o test_profile.stats test_orchestrator.py --types unit
	$(PYTHON) -c "import pstats; p = pstats.Stats('test_profile.stats'); p.sort_stats('cumulative').print_stats(20)"

# Documentation
docs: ## Generate testing documentation
	@echo "Generating testing documentation..."
	$(PYTHON) -c "
import test_orchestrator
import comprehensive_test_suite
import performance_regression_tests
import test_analytics

print('VoiceFlow Testing Framework Documentation')
print('=' * 50)
print()
print('Test Orchestrator:')
print(test_orchestrator.__doc__)
print()
print('Comprehensive Test Suite:')
print(comprehensive_test_suite.__doc__)
print()
print('Performance Regression Tests:')
print(performance_regression_tests.__doc__)
print()
print('Test Analytics:')
print(test_analytics.__doc__)
" > TESTING_DOCS.md

# Environment validation
validate-env: ## Validate testing environment
	@echo "Validating testing environment..."
	$(PYTHON) -c "
import sys
import importlib.util

required_modules = [
    'pytest', 'asyncio', 'sqlite3', 'json', 'pathlib',
    'psutil', 'matplotlib', 'pandas', 'numpy'
]

missing = []
for module in required_modules:
    if importlib.util.find_spec(module) is None:
        missing.append(module)

if missing:
    print(f'Missing required modules: {missing}')
    sys.exit(1)
else:
    print('Environment validation passed')
"

# Continuous monitoring
monitor: ## Start continuous test monitoring
	@echo "Starting continuous test monitoring..."
	$(PYTHON) test_analytics.py --continuous-monitoring --check-interval 24

# Custom test runs
test-custom: ## Run custom test configuration
	@echo "Running custom test configuration..."
	@read -p "Enter test types (space-separated): " types; \
	read -p "Enter test tags (space-separated): " tags; \
	$(PYTHON) test_orchestrator.py --types $$types --tags $$tags --output-dir $(TEST_RESULTS_DIR)

# Performance optimization
optimize: ## Optimize test performance
	@echo "Optimizing test performance..."
	$(PYTHON) -c "
import json
import glob

# Analyze test durations
report_files = glob.glob('$(TEST_RESULTS_DIR)/test_results_*.json')
if not report_files:
    print('No test results found for analysis')
    exit()

with open(sorted(report_files)[-1]) as f:
    results = json.load(f)

# Find slow tests
slow_tests = []
for result in results.get('results', []):
    if result.get('duration', 0) > 30:  # Tests taking more than 30 seconds
        slow_tests.append((result['name'], result['duration']))

if slow_tests:
    print('Slow tests detected:')
    for name, duration in sorted(slow_tests, key=lambda x: x[1], reverse=True):
        print(f'  {name}: {duration:.2f}s')
else:
    print('No slow tests detected')
"

# Integration with external tools
jenkins: ## Generate Jenkins pipeline configuration
	@echo "Generating Jenkins pipeline configuration..."
	@echo "pipeline {" > Jenkinsfile
	@echo "    agent any" >> Jenkinsfile
	@echo "    stages {" >> Jenkinsfile
	@echo "        stage('Test') {" >> Jenkinsfile
	@echo "            steps {" >> Jenkinsfile
	@echo "                sh 'make test-comprehensive'" >> Jenkinsfile
	@echo "            }" >> Jenkinsfile
	@echo "        }" >> Jenkinsfile
	@echo "    }" >> Jenkinsfile
	@echo "}" >> Jenkinsfile
	@echo "Jenkinsfile generated"

# Version info
version: ## Show framework version information
	@echo "VoiceFlow Testing Framework"
	@echo "Version: 1.0.0"
	@echo "Python: $(shell $(PYTHON) --version)"
	@echo "Pytest: $(shell pytest --version | head -1)"
	@echo "Test suites available: $(shell ls tests/test_*.py | wc -l)"
	@echo "Test configuration: $(TEST_CONFIG)"