SHELL := /bin/bash
APPLICATION_NAME="Trade Remedies API Client"
APPLICATION_VERSION=1.0

# Colour coding for output
COLOUR_NONE=\033[0m
COLOUR_GREEN=\033[32;01m
COLOUR_YELLOW=\033[33;01m


.PHONY: help test
help:
		@echo -e "$(COLOUR_GREEN)|--- $(APPLICATION_NAME) [$(APPLICATION_VERSION)] ---|$(COLOUR_NONE)"
		@echo -e "$(COLOUR_YELLOW)make build$(COLOUR_NONE) : Rebuild the last version locally"
		@echo -e "$(COLOUR_YELLOW)make deploy$(COLOUR_NONE) : Rebuild the last version and deploy to pypi"
		@echo -e "$(COLOUR_YELLOW)make local_deploy$(COLOUR_NONE) : Locally build current version and install it to the local repositories (public/caseworker)"
		@echo -e "$(COLOUR_YELLOW)make requirements$(COLOUR_NONE) : Update requirements.txt files"

build:
		rm -rf dist
		mkdir -p dist
		python setup.py sdist

local_deploy:
		rm dist/*.tar.gz
		python setup.py sdist
		cp dist/* ../trade-remedies-public/trade_remedies_client/
		cp dist/* ../trade-remedies-caseworker/trade_remedies_client/
		echo "Please rebuild public and caseworker containers to update the client within the containers"

flake8:
		docker run -it --rm -v requirements:/usr/local -v "$(CURDIR):/app" python sh -c "cd /app && pip install -r requirements/dev.txt && flake8 --count"

black:
		docker run -it --rm -v requirements:/usr/local -v "$(CURDIR):/app" python sh -c "cd /app && pip install -r requirements/dev.txt && black trade_remedies_client --check"

deploy:
		rm dist/*.tar.gz
		python setup.py sdist bdist_wheel
		twine upload

requirements:
		pip-compile --output-file requirements/base.txt requirements.in/base.in
		pip-compile --output-file requirements/dev.txt requirements.in/dev.in
