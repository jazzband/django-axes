all: clean check-manifest pyroma viewdoc
clean:
	if [ -e .long-description.html ]; then rm .long-description.html ; fi
check-manifest:
	check-manifest
viewdoc:
	viewdoc
pyroma:
	pyroma .
testrelease:
	python setup.py sdist --format=zip upload -r test
release:
	python setup.py sdist --format=zip upload
