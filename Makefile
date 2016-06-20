# https://github.com/aclark4life/project-makefile
#
# The MIT License (MIT)
#
# Copyright (c) 2016 Alex Clark
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

.DEFAULT_GOAL=git-commit-edit-push

APP=app
MESSAGE="Update"
PROJECT=project
TMP:=$(shell echo `tmp`)

commit: git-commit-auto-push
co: git-checkout-branches
db: django-migrate django-su
db-clean: django-db-clean-postgres
django-start: django-init
fe-init: npm-init npm-install grunt-init grunt-serve
fe: npm-install grunt-serve
freeze: python-pip-freeze
heroku: heroku-push
install: python3.5-virtualenv python-pip-install
lint: python-flake python-yapf python-wc
migrate: django-migrate
push: git-push
plone-start: plone-init
readme: python-package-readme-test
release: python-package-release
releasetest: python-package-release-test
serve: python-serve
sphinx-start: sphinx-init
static: django-static
test: django-test
vm: vagrant-up
vm-down: vagrant-suspend


# Django
django-db-clean-postgres:
	-dropdb $(PROJECT)-$(APP)
	-createdb $(PROJECT)-$(APP)
django-db-clean-sqlite:
	-rm -f $(PROJECT)-$(APP).sqlite3
django-init:
	-mkdir -p $(PROJECT)/$(APP)
	-django-admin startproject $(PROJECT) .
	-django-admin startapp $(APP) $(PROJECT)/$(APP)
django-install:
	$(MAKE) python-virtualenv
	bin/pip install Django
django-migrate:
	python manage.py migrate
django-migrations:
	python manage.py makemigrations $(APP)
django-migrations-clean:
	rm -rf $(PROJECT)/$(APP)/migrations
	$(MAKE) django-migrations
django-serve:
	python manage.py runserver
django-test:
	python manage.py test
django-shell:
	python manage.py shell
django-static:
	python manage.py collectstatic --noinput
django-su:
	python manage.py createsuperuser

# Git
REMOTE_BRANCHES=`git branch -a |\
	grep remote |\
	grep -v HEAD |\
	grep -v master`
git-checkout-branches:
	-for i in $(REMOTE_BRANCHES) ; do \
        git checkout -t $$i ; done
git-commit-auto-push:
	git commit -a -m $(MESSAGE)
	$(MAKE) git-push
git-commit-edit-push:
	git commit -a
	$(MAKE) git-push
git-push:
	git push

# Heroku
heroku-debug-on:
	heroku config:set DEBUG=1
heroku-debug-off:
	heroku config:unset DEBUG
heroku-push:
	git push heroku
heroku-shell:
	heroku run bash

# Misc
help:
	@echo "\nPlease run \`make\` with one of these targets:\n"
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F:\
        '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}'\
        | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs | tr ' ' '\n' | awk\
        '{print "    - "$$0}'
	@echo "\n"
review:
	open -a "Sublime Text 2" `find $(PROJECT) -name \*.py | grep -v __init__.py`\
        `find $(PROJECT) -name \*.html`

# Node
npm-init:
	npm init
npm-install:
	npm install
grunt-init:
	npm install grunt
	grunt-init Gruntfile
grunt-serve:
	grunt serve

# Plone
plone-heroku:
	-@createuser -s plone > /dev/null 2>&1
	-@createdb -U plone plone > /dev/null 2>&1
	@export PORT=8080 && \
		export USERNAME=admin && \
		export PASSWORD=admin && \
		bin/buildout -c heroku.cfg
plone-init:
	plock --force --no-cache --no-virtualenv .
plone-install:
	$(MAKE) install
	bin/buildout
plone-db-sync:
	bin/buildout -c database.cfg
plone-serve:
	@echo "Zope about to handle requests here:\n\n\thttp://localhost:8080\n"
	@bin/plone fg

# Python
python-clean-pyc:
	find . -name \*.pyc | xargs rm -v
python-flake:
	-flake8 *.py
	-flake8 $(PROJECT)/*.py
	-flake8 $(PROJECT)/$(APP)/*.py
python-package-check:
	check-manifest
	pyroma .
python-package-readme-test:
	rst2html.py README.rst > readme.html; open readme.html
python-package-release:
	python setup.py sdist --format=gztar,zip upload
python-package-release-test:
	python setup.py sdist --format=gztar,zip upload -r test
python-package-test:
	python setup.py test
python-pip-freeze:
	bin/pip freeze | sort > $(TMP)/requirements.txt
	mv -f $(TMP)/requirements.txt .
python-pip-install:
	bin/pip install -r requirements.txt
python-serve:
	@echo "\n\tServing HTTP on http://0.0.0.0:8000\n"
	python -m SimpleHTTPServer
python-virtualenv:
	virtualenv .
python-yapf:
	-yapf -i *.py
	-yapf -i -e $(PROJECT)/urls.py $(PROJECT)/*.py
	-yapf -i $(PROJECT)/$(APP)/*.py
python-wc:
	-wc -l *.py
	-wc -l $(PROJECT)/*.py
	-wc -l $(PROJECT)/$(APP)/*.py

# Sphinx
sphinx-init:
	sphinx-quickstart -q -p "Python Project" -a "Alex Clark" -v 0.0.1 doc
sphinx-serve:
	@echo "\nServing HTTP on http://0.0.0.0:8085 ...\n"
	pushd _build/html; python -m SimpleHTTPServer 8085; popd

# Vagrant
vagrant-box-update:
	vagrant box update
vagrant-clean:
	vagrant destroy
vagrant-down:
	vagrant suspend
vagrant-init:
	vagrant init ubuntu/trusty64
	vagrant up --provider virtualbox
vagrant-up:
	vagrant up --provision

# Django-axes
python3.5-virtualenv:
	virtualenv-3.5 .
