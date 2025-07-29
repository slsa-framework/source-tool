BOLD :=  \033[1m
CYAN :=  \033[36m
GREEN := \033[32m
WHITE := \033[37m
RESET := \033[0m

.PHONY: help
help:
	@printf "${BOLD}${WHITE}SLSA Source Tooling Makefile Help\n=================================${RESET}\n"
	@grep -Eh '^[a-zA-Z_-]+:.*?## .*$$' ${MAKEFILE_LIST} | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "${BOLD}${CYAN}%-25s${RESET}%s\n", $$1, $$2}'

.PHONY: fakes
fakes: ## Rebuild the implementation fakes
	go generate ./...

.PHONY: proto
proto: ## Rebuild the policies and provenance predicate from protocol buffer definitions
	buf generate
