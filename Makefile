.DEFAULT_GOAL := help

.PHONY: install
install: ## Install for development
	uv sync --all-groups
	uv run pre-commit install

.PHONY: format
format: ## Auto-format code
	uv run ruff check --fix
	uv run ruff format

.PHONY: lint
lint: ## Lint code (no auto-fix)
	uv run ruff check
	uv run ruff format --check

.PHONY: typecheck
typecheck: ## Type check with pyright
	uv run pyright mcpscore/

.PHONY: test
test: ## Run tests
	uv run pytest -v

.PHONY: testcov
testcov: ## Run tests with coverage report
	uv run pytest --cov --cov-report=html --cov-report=term-missing
	@echo "Coverage report: htmlcov/index.html"

.PHONY: docs-rules
docs-rules: ## Regenerate docs/rules.mdx from the rule registry
	uv run python scripts/generate_rules_doc.py

.PHONY: docs-serve
docs-serve: docs-rules ## Serve the documentation locally (Mintlify, needs Node)
	cd docs && npx mint dev

.PHONY: docs-check
docs-check: docs-rules ## Validate the documentation (broken links)
	cd docs && npx mint broken-links

.PHONY: release
release: ## Cut a release: create the GitHub Release that publishes to PyPI
	uv run python scripts/release.py

.PHONY: release-dry-run
release-dry-run: ## Run all release checks without creating anything
	uv run python scripts/release.py --dry-run

.PHONY: all
all: lint typecheck testcov ## Run all checks (mirrors CI)

.PHONY: clean
clean: ## Clean build artifacts and caches
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .ruff_cache htmlcov .coverage coverage.xml

.PHONY: help
help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-12s\033[0m %s\n", $$1, $$2}'
