PYTHON ?= python3

.PHONY: help build native test install clean dicts

help:
	@echo "make build    - build dist/zidian (native standalone ELF, no Python needed)"
	@echo "make pyz      - build dist/zidian.pyz (portable single file, needs python3)"
	@echo "make test     - run the validation suite"
	@echo "make install  - pip install this package (provides the 'zidian' command)"
	@echo "make dicts    - regenerate sample dictionaries in dictionaries/"
	@echo "make clean    - remove build artifacts"

build:
	./build.sh

pyz:
	./build.sh --pyz

test:
	$(PYTHON) tests/test_zidian.py

install:
	$(PYTHON) -m pip install .

dicts:
	@mkdir -p dictionaries
	@for p in classic balanced hard max; do \
		PYTHONPATH=src $(PYTHON) -m zidian gen -p $$p --seed 7 -o dictionaries/$$p.txt ; \
	done

clean:
	rm -rf dist build *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
