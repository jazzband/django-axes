================================
Example project for django-axes
================================

Installation
================================
1. Run the install.sh script:

    $ ./install.sh

2. Run the server:

    $ ./manage.py runserver

3. Try the app:

There are two admin accounts created:

- admin:test
- test:test

Open the http://localhost:8000/admin/axes/accessattempt/ URL and log in using admin:admin.

In another browser open http://localhost:8000/admin/ URL and try to log in using test:1 (wrong
password). After your 3-rd wrong login attempt, your account would be locked out.

Testing
================================
To test the app in an easy way do as follows:

    $ ./test.sh
