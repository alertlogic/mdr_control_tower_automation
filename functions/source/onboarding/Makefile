
BASE := $(shell /bin/pwd)
CODE_COVERAGE = 72
PIPENV ?= pipenv
DIST_DIR ?= $(BASE)/functions/packages
$(shell mkdir -p $(DIST_DIR))

################# 
#  Python vars	#
################# 

define VERSION_PYSCRIPT
import re
import ast
from os import path
from setuptools import setup, find_packages

_version_re = re.compile(r"__version__\s+=\s+(.*)")

with open("__init__.py", "rb") as f:
    version = str(ast.literal_eval(_version_re.search(f.read().decode("utf-8")).group(1)))

print(version)
endef

export VERSION_PYSCRIPT

FUNCTION = $(notdir $(shell pwd))
VERSION ?= $(shell python -c '$(VERSION_PYSCRIPT)')

target:
	$(info ${HELP_MESSAGE})
	@exit 0

clean: ##=> Deletes current build environment and latest build
	$(info [*] Who needs all that anyway? Destroying environment....)
	@rm -rf ./build
	@rm -rf ./__pycache__
	#@rm -rf $(DIST_DIR)/$(FUNCTION)_$(VERSION).zip

all: clean build

install: _install_packages _install_dev_packages

shell: 
	@$(PIPENV) shell
	
package: _check_function_definition ##=> Builds package using Docker Lambda container
ifeq ($(DOCKER),1)
	$(info [*] Cleaning up local dev/builds before build task...)
	@$(MAKE) clean FUNCTION="${FUNCTION}"
	$(info [+] Packaging function '$(FUNCTION)' using Docker Lambda -- This may take a while...)
	docker run -v $$PWD:/var/task -it lambci/lambda:build-python3.7 /bin/bash -c 'make _package FUNCTION="${FUNCTION}"'
else
	$(info [*] Cleaning up local builds before build task...)
	@$(MAKE) clean FUNCTION="${FUNCTION}"
	$(info [+] Packaging function '$(FUNCTION)' -- This may take a while...)
	@$(MAKE) _package FUNCTION="${FUNCTION}"
endif

build: _check_function_definition _clone_function_to_build ##=> Same as package except that we don't create a ZIP
	@$(MAKE) _install_deps FUNCTION="${FUNCTION}"


############# 
#  Helpers  #
############# 

_install_packages:
	$(info [*] Install required packages...)
	@$(PIPENV) install

_install_dev_packages:
	$(info [*] Install required dev-packages...)
	@$(PIPENV) install -d

_check_function_definition:
	$(info [*] Checking whether function $(FUNCTION) exists...)

# FUNCTION="<name_of_function>" must be passed as ARG for target or else fail
ifndef FUNCTION
	$(error [!] FUNCTION env not defined...FAIL)
endif

	$(info [*] Checking pipfile exists...)
ifeq ($(wildcard Pipfile),)
	$(error [!] Pipfile dependencies file missing from $(BASE)/$(FUNCTION) folder...)
endif

_clone_function_to_build:
ifeq ($(wildcard build/.),)
	$(info [+] Setting permissions for files under ${FUNCTION}/)
	@find ./ -type f -exec chmod go+r {} \;
	$(info [+] Setting permissions for directories under ./)
	@find ./ -type d -exec chmod go+rx {} \;
	$(info [+] Cloning ${FUNCTION} directory structure to ${FUNCTION}/build)
	@rsync -a -f "+ */" -f "- *" ./ ./build/
	$(info [+] Cloning source files from ./ to ./build)
	@find ./ -type f \
			-not -name "*.pyc" \
			-not -name "*__pycache__" \
			-not -name "requirements.txt" \
			-not -name "Makefile" \
			-not -name "Pipfile" \
			-not -name "Pipfile.lock" \
			-not -name "dist" \
			-not -name "*.swp" \
			-not -name "build" | cut -d '/' -f2- > .results.txt
	@while read line; do \
		ln -f ./$$line ./build/$$line; \
	done < .results.txt
	@rm -f .results.txt
else
	$(info [-] '$(FUNCTION)' already has a development build - Ignoring cloning task...)
endif

_check_dev_definition: _check_function_definition
	$(info [*] Checking whether function $(FUNCTION) development build exists...)

ifeq ($(wildcard ./build/.),)
	$(warning [FIX] run 'make build FUNCTION=$(FUNCTION)' to create one")
	$(error [!] '$(FUNCTION)' doesn't have development build)
endif

_install_deps:
	$(info [+] Installing '$(FUNCTION)' dependencies...")	
	@pip install pipenv
	@$(PIPENV) lock -r > requirements.txt
	@$(PIPENV) run pip install \
		--isolated \
		--disable-pip-version-check \
		-Ur requirements.txt -t build/
	rm -f requirements.txt

# Package application and devs together in expected zip from build
_package: _clone_function_to_build _check_function_definition _install_deps
	@$(MAKE) _zip FUNCTION="${FUNCTION}"

# As its name states: Zip everything up from build
_zip: _check_dev_definition 
	$(info [+] Creating '$(FUNCTION)' ZIP...")
	@cd ./build && zip -rq -9 "$(DIST_DIR)/$(FUNCTION)_$(VERSION).zip" * \
	--exclude "wheel/*" "setuptools/*" "pkg_resources/*" "pip/*" \
			  "easy_install.py" "__pycache__/*" 
	$(info [*] Build complete: $(DIST_DIR)/$(FUNCTION)_$(VERSION).zip)

define HELP_MESSAGE
	Environment variables to be aware of or to hardcode depending on your use case:

	FUNCTION
		Default: not_defined
		Info: Environment variable to declare where source code for lambda is

	DOCKER
		Default: not_defined
		Info: Environment variable to declare whether Docker should be used to build (great for C-deps)

	Common usage:

	...::: Installs all required packages as defined in the pipfile :::...
	$ make install

	...::: Spawn a virtual environment shell :::...
	$ make shell

	...::: Cleans up the environment - Deletes Virtualenv, ZIP builds and Dev env :::...
	$ make clean FUNCTION="slack"

	...::: Creates local dev environment for Python hot-reloading w/ packages:::...
	$ make build FUNCTION="first_function"

	...::: Bundles app and dependencies into a ZIP file :::...
	$ make package FUNCTION="email"

	...::: Bundles app and dependencies into a ZIP file using Docker:::...
	$ make package FUNCTION="email" DOCKER=1

	...::: Run SAM Local API Gateway :::...
	$ make run

	...::: Run Pytest under tests/ with pipenv :::...
	$ make test

endef


