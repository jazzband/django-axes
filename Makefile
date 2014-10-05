all: clean check-manifest viewdoc
clean:
	if [ -e .long-description.html ]; then rm .long-description.html ; fi
check-manifest:
	check-manifest
viewdoc:
	viewdoc
