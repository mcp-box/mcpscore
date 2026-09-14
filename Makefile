.DEFAULT_GOAL := help

.PHONY: install
install: ## Install for development
	uv sync --all-groups
	uv run pre-commit install

.PHONY: format
format: ## Auto-format code
	uv run ruff check --fix
	uv run ruff format

.PHONY: precommit
precommit: ## Run the pinned pre-commit hooks — the same gate CI's lint job runs
# SKIP mirrors ci.yml: no-commit-to-branch would fail on main and typecheck runs
# pyright on its own. The hooks stay active for real commits.
	SKIP=no-commit-to-branch,typecheck uv run pre-commit run --all-files

.PHONY: lint
lint: precommit ## Lint code (no auto-fix): CI's hooks, then the working tree
# The hooks check files git tracks; the ruff calls below also cover untracked
# files in the working tree. Both are needed; see AGENTS.md.
	uv run ruff check
	uv run ruff format --check

.PHONY: typecheck
typecheck: ## Type check with pyright
	uv run pyright mcpscore/ scripts/

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
all: lint typecheck testcov test-npm ## Run all checks (mirrors CI)

.PHONY: test-npm
test-npm: ## Test the npm launcher (requires Node.js 18+)
	npm --prefix npm test

.PHONY: clean
clean: ## Clean build artifacts and caches
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .ruff_cache htmlcov .coverage coverage.xml

.PHONY: help
help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-12s\033[0m %s\n", $$1, $$2}'
