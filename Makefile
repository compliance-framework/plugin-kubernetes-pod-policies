# Makefile for building and pushing OPA policies to a registry

# Variables
REGISTRY_URL := ghcr.io
NAMESPACE := chris-cmsoft
POLICY_NAME := local-ssh-policies
VERSION := latest
POLICY_DIR := ./ssh # Directory containing your .rego files

# Build and Push Commands
.PHONY: all build bundle push clean

# Default action
all: test check build push clean

# Check if OPA CLI is installed
OPA := $(shell command -v opa 2> /dev/null)
ifeq ($(OPA),)
$(error "opa CLI not found. Please install it: https://www.openpolicyagent.org/docs/latest/cli/")
endif

# Check if Docker CLI is installed

CONTAINER_CLI := ""
DOCKER := $(shell command -v docker 2> /dev/null)
PODMAN := $(shell command -v podman 2> /dev/null)
ifeq ($(DOCKER),)
	PODMAN := := $(shell command -v podman 2> /dev/null)
	ifeq ($(PODMAN),)
		$(error "either docker or podman CLI is required.")
	else
		CONTAINER_CLI = PODMAN
	endif
else
	CONTAINER_CLI = DOCKER
endif

test:
	@echo "Testing policies..."
	@OPA test policies

# Build the policies
check:
	@echo "Checking policies..."
	@opa check policies

# Bundle the policies into a tarball for OCI registry
build: clean
	@echo "Bundling policies..."
	@mkdir -p dist/
	@opa build -b policies -o dist/bundle.tar.gz

# Push the bundled policies to an OCI-compliant registry
push: build
	@echo "Pushing bundle to registry..."
	@# Log in to the registry if necessary
	@$(CONTAINER_CLI) login $(REGISTRY_URL)
	@# Push the bundle as an OCI artifact
	@$(CONTAINER_CLI) cp dist/bundle.tar.gz $(REGISTRY_URL)/$(NAMESPACE)/$(POLICY_NAME):$(VERSION)
	@echo "Bundle pushed successfully to $(REGISTRY_URL)/$(NAMESPACE)/$(POLICY_NAME):$(VERSION)"

# Clean up build artifacts
clean:
	@echo "Cleaning up..."
	@rm -f dist/bundle.tar.gz
