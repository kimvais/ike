all: clean doc pypi

doc:
	pandoc -t rst README.md > README.rst
	cp README.rst docs/readme.rst
	sphinx-apidoc -o docs/ ike
	sphinx-build docs docs/_build

clean:
	rm -rf __pycache__ build dist README.rst || true

pypi:
	python setup.py sdist bdist upload
