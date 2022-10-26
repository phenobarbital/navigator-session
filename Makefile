venv:
	python3.9 -m venv .venv
	echo 'run `source .venv/bin/activate` to start develop Navigator-Session'

setup:
	pip install wheel==0.37.1
	pip install -e .

develop:
	pip install wheel==0.37.1
	pip install -e .
	pip install -Ur docs/requirements-dev.txt
	flit install --symlink

release:
	lint test clean
	flit publish

format:
	python -m black navigator_session

lint:
	python -m pylint --rcfile .pylintrc navigator_session/*.py
	python -m black --check navigator_session

test:
	python -m coverage run -m navigator_session.tests
	python -m coverage report
	python -m mypy navigator_session/*.py

perf:
	python -m unittest -v navigator_session.tests.perf

distclean:
	rm -rf .venv
