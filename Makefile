all: clean doc

release: pypi

clean-doc:
	rm docs/ike.rst docs/ike.util.rst docs/modules.rst || true

doc: clean-doc
	pandoc -t rst README.md > README.rst
	cp README.rst docs/readme.rst
	sphinx-apidoc -o docs/ ike
	sphinx-build docs docs/_build
	git add docs/*.rst

clean: clean-doc
	rm -rf __pycache__ build dist README.rst || true

pypi:
	python setup.py sdist bdist upload
