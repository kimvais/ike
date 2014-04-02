all: clean doc pypi

doc:
	pandoc -t rst README.md > README.rst

clean:
	rm -rf __pycache__ build dist README.rst || true

pypi:
	python setup.py sdist bdist upload
