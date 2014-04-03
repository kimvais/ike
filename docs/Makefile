doc:
	pandoc -t rst README.md > README.rst
	cp README.rst docs/readme.rst
	sphinx-apidoc -o docs/ ike
	sphinx-build docs docs/_build

