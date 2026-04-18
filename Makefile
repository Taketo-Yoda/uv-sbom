.PHONY: setup
setup:
	git config core.hooksPath .githooks
	@echo "Git hooks activated. .githooks/pre-push will run quality checks on every push."
