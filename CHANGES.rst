
Changes
=======

8.1.0 (2025-12-19)
------------------

- Add Persion (fa) translations for django-axes.
  [AmirAli-BahramJerdi]
- Add individual attempt expiry support.
  [kuldeepkhatke]
- Add checks for missing ip_address in lockout params.
  [shayanTaki]
- Add missing ``settings.AXES_IPWARE_PROXY_ORDER`` documentation.
  [ram98kgp]
- Enhance ``get_lockout_response`` to receive original response as parameter.
  [mounirmesselmeni]
- Update documentation.
- Add Python 3.14 support.
- Add Django 6.0 support.
- Remove Python 3.9 support (EOL).
- Remove Django 5.1 support (EOL).

8.0.0 (2025-05-10)
------------------

- Move all database related logic to the default ``axes.handlers.database.AxesDatabaseHandler``.
  [nefrob]

7.1.0 (2025-04-23)
------------------

- Provide credentials to expired credentials cleanup method.
  [parul-aro]
- Update support matrix for Django 5.2.
  [mkniewallner]
- Fix documentation.
  [chango-goat]


7.0.2 (2025-02-19)
------------------

- Fix documentation.
  [Jacobus-afk]
- Default to using ``settings.AUTH_USER_MODEL.USERNAME_FIELD`` for resolving ``settings.AXES_USERNAME_FORM_FIELD`` if otherwise unset (previously "username").
  [amneher]


7.0.1 (2024-12-02)
------------------

- Add Python 3.13 support.
  [aleksihakli]
- Deprecate Python 3.8 support.
  [aleksihakli]


7.0.0 (2024-10-02)
------------------

- Add support for dynamic cooloff time calculation from request. This is a breaking change. Please see `version 7 upgrade notes in the documentation <https://github.com/jazzband/django-axes/blob/4e89d72b92db044ff3f6b23ea2ab2e681211c98e/docs/2_installation.rst#version-7-breaking-changes-and-upgrading-from-django-axes-version-6>`_.
  [browniebroke]


6.5.2 (2024-09-21)
------------------

- Add test matrix support for Django 5.1.
- Drop support for EOL Django 3.2.
- Drop support for PyPy 3.10.


6.5.1 (2024-07-01)
------------------

- Make 0007_alter_accessattempt_unique_together.py migration backwards compatible.
  [hirotasoshu]


6.5.0 (2024-06-11)
------------------

- Add session hash to access log.
  [sevdog]


6.4.0 (2024-03-04)
------------------

- Add support for Python 3.12 and Django 5.0, drop support for Django 4.1.
  [aleksihakli]


6.3.1 (2024-03-04)
------------------

- Drop ``setuptools`` and ``pkg_resources`` dependencies.
  [Viicos]


6.3.0 (2023-12-27)
------------------

- Add async support to middleware.
  [Taikono-Himazin]


6.2.0 (2023-12-08)
------------------

- Update documentation.
  [funkybob]
- Add new management command ``axes_reset_ip_username``.
  [p-l-]
- Add French translations.
  [laulaz]
- Avoid running data migration on incorrect databases.
  [christianbundy]


6.1.1 (2023-08-01)
------------------

- Fix ``TransactionManagementError`` when using the database handler
  with a custom database with for ``AccessAttempt`` or ``AccessFailureLog``.
  [hirotasoshu]


6.1.0 (2023-07-30)
------------------

- Set ``AXES_SENSITIVE_PARAMETERS`` default value to ``["username", "ip_address"]`` in addition to the ``AXES_PASSWORD_FORM_FIELD`` configuration flag.
  This masks the username and IP address fields by default in the logs when writing information about login attempts to the application logs.
  Reverting to old configuration default of ``[]`` can be done by setting ``AXES_SENSITIVE_PARAMETERS = []`` in the Django project settings file.
  [GitRon]
- Improve documentation on GDPR and privacy notes and configuration flags.
  [GitRon]


6.0.5 (2023-07-01)
------------------

- Add Indonesion translation.
  [kiraware]


6.0.4 (2023-06-22)
------------------

- Remove unused methods from AxesStandaloneBackend.
  [314eter]


6.0.3 (2023-06-18)
------------------

- Add username to admin fieldsets.
  [sevdog]


6.0.2 (2023-06-13)
------------------

- Add Django system checks for validating callable import path settings.
  [iafisher]
- Improve documentation.
  [hirotasoshu]
- Improve repository issue and PR templates.
  [hirotasoshu]


6.0.1 (2023-05-17)
------------------

- Fine-tune CI pipelines and RTD build requirements.
  [aleksihakli]


6.0.0 (2023-05-17)
------------------

Version 6 is a breaking release. Please see the documentation for upgrade instructions.

- Deprecate Python 3.7 support.
  [aleksihakli]
- Deprecate ``is_admin_site`` API call with misleading naming.
  [hirotasoshu]
- Add ``AXES_LOCKOUT_PARAMETERS`` configuration flag that will supersede ``AXES_ONLY_USER_FAILURES``, ``AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP``, ``AXES_LOCK_OUT_BY_USER_OR_IP``, and ``AXES_USE_USER_AGENT`` configurations. Add deprecation warnings for old flags. See project documentation on RTD for update instructions.
  [hirotasoshu]
- Improve translations.
  [hirotasoshu]
- Use Django ``cache.incr`` API for atomic cached failure counting
  [hirotasoshu, aleksihakli]
- Make ``django-ipware`` an optional dependency. Install it with e.g. ``pip install django-axes[ipware]`` package and extras specifier. [aleksihakli]
- Deprecate and rename old configuration flags. Old flags will be removed in or after version ``6.1``. [aleksihakli]
   * ``AXES_PROXY_ORDER`` is now ``AXES_IPWARE_PROXY_ORDER``,
   * ``AXES_PROXY_COUNT`` is now ``AXES_IPWARE_PROXY_COUNT``,
   * ``AXES_PROXY_TRUSTED_IPS`` is now ``AXES_IPWARE_PROXY_TRUSTED_IPS``, and
   * ``AXES_META_PRECEDENCE_ORDER`` is now ``AXES_IPWARE_META_PRECEDENCE_ORDER``.
- Set 429 as the default lockout response code. [hirotasoshu]


5.41.1 (2023-04-16)
-------------------

- Fix sensitive parameter logging for database handler. [stereodamage]

5.41.0 (2023-04-02)
-------------------

- Fix tests. [hirotasoshu]
- Add ``AXES_CLIENT_CALLABLE`` setting. [hirotasoshu]
- Update Python, Django, and package versions. [hramezani]


5.40.1 (2022-11-24)
-------------------

- Fix bug in user agent request blocking. [PetrDlouhy]


5.40.0 (2022-11-19)
-------------------

- Update packages and linters for new version support.
  [hramezani]
- Update documentation links.
  [Arhell]
- Use importlib instead of setuptools for Python 3.8+.
  [jedie]
- Python 3.11 support.
  [joshuadavidthomas]
- Documentation improvements.
  [nsht]
- Documentation improvements.
  [timgates42]


5.39.0 (2022-08-18)
-------------------

- Utilize new backend class in tests to fix false negative system check warnings.
  [simonkern]


5.38.0 (2022-08-16)
-------------------

- Adjust changelog so release notes are correctly visible on PyPy and released package.
  [aleksihakli]


5.37.0 (2022-08-16)
-------------------

- Add Django 4.1 support. PyPy 3.8 has a known issue with Django 4.1 and is exempted.
  [hramezani]


5.36.0 (2022-07-17)
-------------------

- Add ``AxesStandaloneBackend`` without ``ModelBackend`` dependencies.
  [jcgiuffrida]


5.35.0 (2022-06-01)
-------------------

- Add Arabic translations.
  [YDA93]


5.34.0 (2022-05-28)
-------------------

- Improve German translations.
  [GitRon]


5.33.0 (2022-05-16)
-------------------

- Migrate MD5 cache key digests to SHA256.
  [aleksihakli]
- Improve and streamline startup logging.
  [ShaheedHaque]
- Improve module typing.
  [hramezani]
- Add support for float or partial hours for ``AXES_COOLOFF_TIME``.
  [hramezani]


5.32.0 (2022-04-08)
-------------------

- Add support for persistent failure logging
  where failed login attempts are persisted in the database
  until a specific threshold is reached.
  [p1-gdd]
- Add support for not resetting login times when users
  try to login during the lockout cooloff period.
  [antoine-42]


5.31.0 (2022-01-08)
-------------------

- Adjust version specifiers for newer Python and other package versions.
  Set package minimum Python version to 3.7.
  Relax ``django-ipware`` version requirements to allow newer versions.
  [aleksihakli]


5.30.0 (2022-01-08)
-------------------

- Fix package build error in 5.29.0 to allow publishing.
  [aleksihakli]


5.29.0 (2022-01-08)
-------------------

- Drop Python 3.6 support.
  [aleksihakli]


5.28.0 (2021-12-14)
-------------------

- Drop Django < 3.2 support.
  [hramezani]
- Add Django 4.0 to test matrix.
  [hramezani]


5.27.0 (2021-11-04)
-------------------

- Fix ``pkg_resources`` missing for package version resolution on runtime
  due to ``setuptools`` not being a runtime dependency.
  [asherf]
- Add Python 3.10 and Django 3.2 support.
  [hramezani]


5.26.0 (2021-10-11)
-------------------

- Fix ``AXES_USERNAME_CALLABLE`` not receiving ``credentials`` attribute
  in Axes middleware lockout response when user is locked out.
  [rootart]


5.25.0 (2021-09-19)
-------------------

- Fix duplicated AccessAttempts
  with updated database model ``unique_together`` constraints
  and data and schema migration.
  [PetrDlouhy]


5.24.0 (2021-09-09)
-------------------

- Use atomic transaction for updating AccessAttempts in database handler.
  [okapies]


5.23.0 (2021-09-02)
-------------------

- Pass ``request`` as argument to ``AXES_CLIENT_STR_CALLABLE``.
  [sarahboyce]


5.22.0 (2021-08-31)
-------------------

- Improve ``failures_since_start`` handling by moving the counter incrementation
  from non-atomic Python code call to atomic database function.
  [okapies]
- Add publicly available ``request.axes_failures_since_start`` attribute.
  [okapies]


5.21.0 (2021-08-19)
-------------------

- Add configurable lockout HTTP status code responses
  with the new ``AXES_HTTP_RESPONSE_CODE`` setting.
  [phil-bell]


5.20.0 (2021-06-29)
-------------------

- Improve race condition handling in e.g. multi-process environments by using
  ``get_or_create`` for access attempt fetching and updates.
  [uli-klank]


5.19.0 (2021-06-16)
-------------------

- Add Polish locale.
  [Quadric]


5.18.0 (2021-06-09)
-------------------

- Fix ``default_auto_field`` warning.
  [zkanda]


5.17.0 (2021-06-05)
-------------------

- Fix ``default_app_config`` deprecation.
  Django 3.2 automatically detects ``AppConfig`` and therefore this setting is no longer required.
  [nikolaik]


5.16.0 (2021-05-19)
-------------------

- Add ``AXES_CLIENT_STR_CALLABLE`` setting.
  [smtydn]


5.15.0 (2021-05-03)
-------------------

- Add option to cleanse sensitive GET and POST params in database handler
  with the ``AXES_SENSITIVE_PARAMETERS`` setting.
  [mcoconnor]


5.14.0 (2021-04-06)
-------------------

- Improve message formatting for lockout message and translations.
  [ashokdelphia]
- Remove support for Django 3.0.
  [hramezani]
- Add support for Django 3.2.
  [hramezani]


5.13.1 (2021-02-22)
-------------------

- Default ``AXES_VERBOSE`` to ``AXES_ENABLED`` configuration setting,
  disabling verbose startup logging when Axes itself is disabled.
  [christianbundy]
- Update documentation.
  [KStenK]


5.13.0 (2021-02-15)
-------------------

- Add support for resetting attempts with cache backend.
  [nattyg93]


5.12.0 (2021-01-07)
-------------------

- Clean up test structure and migrate tests outside
  the main package for a smaller wheel distributions.
  [aleksihakli]
- Move configuration to pyproject.toml for cleaner layout.
  [aleksihakli]
- Clean up test settings override configuration.
  [hramezani]


5.11.1 (2021-01-06)
-------------------

- Fix cache entry creations for None username.
  [cabarnes]


5.11.0 (2021-01-05)
-------------------

- Add lockout view CORS support with ``AXES_ALLOWED_CORS_ORIGINS`` configuration flag.
  [vladox]
- Add missing ``@wraps`` decorator to ``axes.decorators.axes_dispatch``.
  [aleksihakli]


5.10.1 (2021-01-04)
-------------------

- Add ``DEFAULT_AUTO_FIELD`` to test settings.
  [hramezani]
- Fix documentation language.
  [danielquinn]
- Fix Python package version specifiers and remove redundant imports.
  [aleksihakli]


5.10.0 (2020-12-18)
-------------------

- Deprecate stock DRF support from 5.8.0,
  require users to set it up per project.
  Check the documentation for more information.
  [aleksihakli]


5.9.1 (2020-12-02)
------------------

- Move tests to GitHub Actions
  [jezdez]
- Fix running Axes code in middleware when ``AXES_ENABLED`` is ``False``.
  [ashokdelphia]


5.9.0 (2020-11-05)
------------------

- Add Python 3.9 support.
  [hramezani]
- Prevent ``AccessAttempt`` creation with database handler when
  username is not set and ``AXES_ONLY_USER_FAILURES`` setting is not set.
  [hramezani]


5.8.0 (2020-10-16)
------------------

- Improve Django REST Framework (DRF) integration.
  [Anatoly]


5.7.1 (2020-09-27)
------------------

- Adjust settings import and handling chain
  for cleaner module import and invocation order.
  [aleksihakli]
- Adjust the use of ``AXES_ENABLED`` flag so that
  imports are always done the same way and initial log
  is written regardless of the setting and it only affects
  code that is decorated or wrapped with ``toggleable``.
  [alekshakli]


5.7.0 (2020-09-26)
------------------

- Deprecate ``AXES_LOGGER`` Axes setting and move to ``__name__``
  based logging and fully qualified Python module name log identifiers.
  [aleksihakli]


5.6.2 (2020-09-20)
------------------

- Fix regression in ``axes_reset_user`` management command.
  [aleksihakli]


5.6.1 (2020-09-17)
------------------

- Improve test dependency management and upgrade black code formatter.
  [smithdc1]


5.6.0 (2020-09-12)
------------------

- Add proper development ``subTest`` support via ``pytest-subtests`` package.
  [smithdc1]
- Deprecate ``django-appconf`` and use plain settings for Axes.
  [aleksihakli]


5.5.2 (2020-09-11)
------------------

- Update deprecating use of the ``request.is_ajax`` method.
  [smithdc1]


5.5.1 (2020-09-10)
------------------

- Update deprecated uses of Django modules and members.
  [smithdc1]


5.5.0 (2020-08-21)
------------------

- Add support for locking requests based on
  username OR IP address with inclusive or
  using the ``LOCK_OUT_BY_USER_OR_IP`` flag.
  [PetrDlouhy]
- Deprecate Signal ``providing_args`` for Django 3.1 support.
  [coredumperror]


5.4.3 (2020-08-06)
------------------

- Add Django 3.1 support.
  [hramezani]


5.4.2 (2020-07-28)
------------------

- Add ABC or abstract base class implementation for handlers.
  [jorlugaqui]


5.4.1 (2020-07-03)
------------------

- Fix code styling for linters.
  [aleksihakli]


5.4.0 (2020-07-03)
------------------

- Propagate username to lockout view in URL parameters.
  [PetrDlouhy]
- Update CAPTCHA examples.
  [PetrDlouhy]
- Upgrade django-ipware to version 3.
  [hramezani,mnislam01]


5.3.5 (2020-07-02)
------------------

- Restrict ipware version for version compatibility.
  [aleksihakli]


5.3.4 (2020-06-09)
------------------

- Deprecate Django 1.11 LTS support.
  [aleksihakli]


5.3.3 (2020-05-22)
------------------

- Fix ``AXES_ONLY_ADMIN_SITE`` functionality when
  no default admin site is defined in the URL configuration.
  [igor-shevchenko]


5.3.2 (2020-05-15)
------------------

- Fix AppConf settings prefix for Fargate.
  [marksweb]


5.3.1 (2020-03-23)
------------------

- Fix null byte ValueError bug in ORM.
  [ddimmich]


5.3.0 (2020-03-10)
------------------

- Improve Django REST Framework compatibility.
  [I0x4dI]


5.2.2 (2020-01-08)
------------------

- Add missing proxy implementation for
  ``axes.handlers.proxy.AxesProxyHandler.get_failures``.
  [aleksihakli]


5.2.1 (2020-01-08)
------------------

- Add django-reversion compatibility notes.
  [mark-mishyn]
- Add pluggable lockout responses and the
  ``AXES_LOCKOUT_CALLABLE`` configuration flag.
  [aleksihakli]


5.2.0 (2020-01-01)
------------------

- Add a test handler.
  [aidanlister]


5.1.0 (2019-12-29)
------------------

- Add pluggable user account whitelisting and the
  ``AXES_WHITELIST_CALLABLE`` configuration flag.
  [aleksihakli]


5.0.20 (2019-12-01)
-------------------

- Fix django-allauth compatibility issue.
  [hramezani]
- Improve tests for login attempt monitoring.
  [hramezani]
- Add reverse proxy documentation.
  [ckcollab]
- Update OAuth documentation examples.
  [aleksihakli]


5.0.19 (2019-11-06)
-------------------

- Optimize access attempt fetching in database handler.
  [hramezani]
- Optimize request data fetching in proxy handler.
  [hramezani]


5.0.18 (2019-10-17)
-------------------

- Add ``cooloff_timedelta`` context variable to lockout responses.
  [jstockwin]


5.0.17 (2019-10-15)
-------------------

- Safer string formatting for user input.
  [aleksihakli]


5.0.16 (2019-10-15)
-------------------

- Fix string formatting bug in logging.
  [zerolab]


5.0.15 (2019-10-09)
-------------------

- Add ``AXES_ENABLE_ADMIN`` flag.
  [flannelhead]


5.0.14 (2019-09-28)
-------------------

- Docs, CI pipeline, and code formatting improvements
  [aleksihakli]


5.0.13 (2019-08-30)
-------------------

- Python 3.8 and PyPy support.
  [aleksihakli]
- Migrate to ``setuptools_scm`` and automatic versioning.
  [aleksihakli]


5.0.12 (2019-08-05)
-------------------

- Support callables for ``AXES_COOLOFF_TIME`` setting.
  [DariaPlotnikova]


5.0.11 (2019-07-25)
-------------------

- Fix typo in rST formatting that prevented 5.0.10 release to PyPI.
  [aleksihakli]


5.0.10 (2019-07-25)
-------------------

- Refactor type checks for ``axes.helpers.get_client_cache_key``
  for framework compatibility, fixes #471.
  [aleksihakli]


5.0.9 (2019-07-11)
------------------

- Add better handling for attempt and log resets by moving them
  into handlers which allows customization and more configurability.
  Unimplemented handlers raise ``NotImplementedError`` by default.
  [aleksihakli]
- Add Python 3.8 dev version and PyPy to the Travis test matrix.
  [aleksihakli]


5.0.8 (2019-07-09)
------------------

- Add ``AXES_ONLY_ADMIN_SITE`` flag for only running Axes on admin site.
  [hramezani]
- Add ``axes_reset_logs`` command for removing old AccessLog records.
  [tlebrize]
- Allow ``AxesBackend`` subclasses to pass the ``axes.W003`` system check.
  [adamchainz]


5.0.7 (2019-06-14)
------------------

- Fix lockout message showing when lockout is disabled
  with the ``AXES_LOCK_OUT_AT_FAILURE`` setting.
  [mogzol]

- Add support for callable ``AXES_FAILURE_LIMIT`` setting.
  [bbayles]


5.0.6 (2019-05-25)
------------------

- Deprecate ``AXES_DISABLE_SUCCESS_ACCESS_LOG`` flag in favour of
  ``AXES_DISABLE_ACCESS_LOG`` which has mostly the same functionality.
  Update documentation to better reflect the behaviour of the flag.
  [aleksihakli]


5.0.5 (2019-05-19)
------------------

- Change the lockout response calculation to request flagging
  instead of exception throwing in the signal handler and middleware.
  Move request attribute calculation from middleware to handler layer.
  Deprecate ``axes.request.AxesHttpRequest`` object type definition.
  [aleksihakli]

- Deprecate the old version 4.x ``axes.backends.AxesModelBackend`` class.
  [aleksihakli]

- Improve documentation on attempt tracking, resets, Axes customization,
  project and component compatibility and integrations, and other things.
  [aleksihakli]


5.0.4 (2019-05-09)
------------------

- Fix regression with OAuth2 authentication backends not having remote
  IP addresses set and throwing an exception in cache key calculation.
  [aleksihakli]


5.0.3 (2019-05-08)
------------------

- Fix ``django.contrib.auth`` module ``login`` and ``logout`` functionality
  so that they work with the handlers without the an ``AxesHttpRequest``
  to improve cross compatibility with other Django applications.
  [aleksihakli]

- Change IP address resolution to allow empty or missing addresses.
  [aleksihakli]

- Add error logging for missing request attributes in the handler layer
  so that users get better indicators of misconfigured applications.
  [aleksihakli]


5.0.2 (2019-05-07)
------------------

- Add ``AXES_ENABLED`` setting for disabling Axes with e.g. tests
  that use Django test client ``login``, ``logout``, and ``force_login``
  methods, which do not supply the ``request`` argument to views,
  preventing Axes from functioning correctly in certain test setups.
  [aleksihakli]


5.0.1 (2019-05-03)
------------------

- Add changelog to documentation.
  [aleksihakli]


5.0 (2019-05-01)
----------------

- Deprecate Python 2.7, 3.4 and 3.5 support.
  [aleksihakli]

- Remove automatic decoration and monkey-patching of Django views and forms.
  Decorators are available for login function and method decoration as before.
  [aleksihakli]

- Use backend, middleware, and signal handlers for tracking
  login attempts and implementing user lockouts.
  [aleksihakli, jorlugaqui, joshua-s]

- Add ``AxesDatabaseHandler``, ``AxesCacheHandler``, and ``AxesDummyHandler``
  handler backends for processing user login and logout events and failures.
  Handlers are configurable with the ``AXES_HANDLER`` setting.
  [aleksihakli, jorlugaqui, joshua-s]

- Improve management commands and separate commands for resetting
  all access attempts, attempts by IP, and attempts by username.
  New command names are ``axes_reset``, ``axes_reset_ip`` and ``axes_reset_username``.
  [aleksihakli]

- Add support for string import for ``AXES_USERNAME_CALLABLE``
  that supports dotted paths in addition to the old
  callable type such as a function or a class method.
  [aleksihakli]

- Deprecate one argument call signature for ``AXES_USERNAME_CALLABLE``.
  From now on, the callable needs to accept two arguments,
  the HttpRequest and credentials that are supplied to the
  Django ``authenticate`` method in authentication backends.
  [aleksihakli]

- Move ``axes.attempts.is_already_locked`` function to ``axes.handlers.AxesProxyHandler.is_locked``.
  Various other previously undocumented methods have been deprecated and moved inside the project.
  The new documented public APIs can be considered as stable and can be safely utilized by other projects.
  [aleksihakli]

- Improve documentation layouting and contents. Add public API reference section.
  [aleksihakli]


4.5.4 (2019-01-15)
------------------

- Improve README and documentation
  [aleksihakli]


4.5.3 (2019-01-14)
------------------

- Remove the unused ``AccessAttempt.trusted`` flag from models
  [aleksihakli]

- Improve README and Travis CI setups
  [aleksihakli]


4.5.2 (2019-01-12)
------------------

- Added Turkish translations
  [obayhan]


4.5.1 (2019-01-11)
------------------

- Removed duplicated check that was causing issues when using APIs.
  [camilonova]

- Added Russian translations
  [lubicz-sielski]


4.5.0 (2018-12-25)
------------------

- Improve support for custom authentication credentials using the
  ``AXES_USERNAME_FORM_FIELD`` and ``AXES_USERNAME_CALLABLE`` settings.
  [mastacheata]

- Updated behaviour for fetching username from request or credentials:
  If no ``AXES_USERNAME_CALLABLE`` is configured, the optional
  ``credentials`` that are supplied to the axes utility methods
  are now the default source for client username and the HTTP
  request POST is the fallback for fetching the user information.
  ``AXES_USERNAME_CALLABLE`` implements an alternative signature with two
  arguments ``request, credentials`` in addition to the old ``request``
  call argument signature in a backwards compatible fashion.
  [aleksihakli]

- Add official support for the Django 2.1 version and Python 3.7.
  [aleksihakli]

- Improve the requirements, documentation, tests, and CI setup.
  [aleksihakli]


4.4.3 (2018-12-08)
------------------

- Fix MANIFEST.in missing German translations
  [aleksihakli]

- Add `AXES_RESET_ON_SUCCESS` configuration flag
  [arjenzijlstra]


4.4.2 (2018-10-30)
------------------

- fix missing migration and add check to prevent it happening again.
  [markddavidoff]


4.4.1 (2018-10-24)
------------------

- Add a German translation
  [adonig]

- Documentation wording changes
  [markddavidoff]

- Use `get_client_username` in `log_user_login_failed` instead of credentials
  [markddavidoff]

- pin prospector to 0.12.11, and pin astroid to 1.6.5
  [hsiaoyi0504]


4.4.0 (2018-05-26)
------------------

- Added AXES_USERNAME_CALLABLE
  [jaadus]


4.3.1 (2018-04-21)
------------------

- Change custom authentication backend failures from error to warning log level
  [aleksihakli]

- Set up strict code linting for CI pipeline that fails builds if linting does not pass
  [aleksihakli]

- Clean up old code base and tests based on linter errors
  [aleksihakli]


4.3.0 (2018-04-21)
------------------

- Refactor and clean up code layout
  [aleksihakli]

- Add prospector linting and code checks to toolchain
  [aleksihakli]

- Clean up log message formatting and refactor type checks
  [EvaSDK]

- Fix faulty user locking with user agent when AXES_ONLY_USER_FAILURES is set
  [EvaSDK]


4.2.1 (2018-04-18)
------------------

- Fix unicode string interpolation on Python 2.7
  [aleksihakli]


4.2.0 (2018-04-13)
------------------

- Add configuration flags for client IP resolving
  [aleksihakli]

- Add AxesModelBackend authentication backend
  [markdaviddoff]


4.1.0 (2018-02-18)
------------------

- Add AXES_CACHE setting for configuring `axes` specific caching.
  [JWvDronkelaar]

- Add checks and tests for faulty LocMemCache usage in application setup.
  [aleksihakli]


4.0.2 (2018-01-19)
------------------

- Improve Windows compatibility on Python < 3.4 by utilizing win_inet_pton
  [hsiaoyi0504]

- Add documentation on django-allauth integration
  [grucha]

- Add documentation on known AccessAttempt caching configuration problems
  when using axes with the `django.core.cache.backends.locmem.LocMemCache`
  [aleksihakli]

- Refactor and improve existing AccessAttempt cache reset utility
  [aleksihakli]


4.0.1 (2017-12-19)
------------------

- Fixes issue when not using `AXES_USERNAME_FORM_FIELD`
  [camilonova]


4.0.0 (2017-12-18)
------------------

- *BREAKING CHANGES*. `AXES_BEHIND_REVERSE_PROXY` `AXES_REVERSE_PROXY_HEADER`
  `AXES_NUM_PROXIES` were removed in order to use `django-ipware` to get
  the user ip address
  [camilonova]

- Added support for custom username field
  [kakulukia]

- Customizing Axes doc updated
  [pckapps]

- Remove filtering by username
  [camilonova]

- Fixed logging failed attempts to authenticate using a custom authentication
  backend.
  [D3X]


3.0.3 (2017-11-23)
------------------

- Test against Python 2.7.
  [mbaechtold]

- Test against Python 3.4.
  [pope1ni]


3.0.2 (2017-11-21)
------------------

- Added form_invalid decorator. Fixes #265
  [camilonova]


3.0.1 (2017-11-17)
------------------

- Fix DeprecationWarning for logger warning
  [richardowen]

- Fixes global lockout possibility
  [joeribekker]

- Changed the way output is handled in the management commands
  [ataylor32]


3.0.0 (2017-11-17)
------------------

- BREAKING CHANGES. Support for Django >= 1.11 and signals, see issue #215.
  Drop support for Python < 3.6
  [camilonova]


2.3.3 (2017-07-20)
------------------

- Many tweaks and handles successful AJAX logins.
  [Jack Sullivan]

- Add tests for proxy number parametrization
  [aleksihakli]

- Add AXES_NUM_PROXIES setting
  [aleksihakli]

- Log failed access attempts regardless of settings
  [jimr]

- Updated configuration docs to include AXES_IP_WHITELIST
  [Minkey27]

- Add test for get_cache_key function
  [jorlugaqui]

- Delete cache key in reset command line
  [jorlugaqui]

- Add signals for setting/deleting cache keys
  [jorlugaqui]


2.3.2 (2016-11-24)
------------------

- Only look for lockable users on a POST
  [schinckel]

- Fix and add tests for IPv4 and IPv6 parsing
  [aleksihakli]


2.3.1 (2016-11-12)
------------------

- Added settings for disabling success accesslogs
  [Minkey27]

- Fixed illegal IP address string passed to inet_pton
  [samkuehn]


2.3.0 (2016-11-04)
------------------

- Fixed ``axes_reset`` management command to skip "ip" prefix to command
  arguments.
  [EvaMarques]

- Added ``axes_reset_user`` management command to reset lockouts and failed
  login records for given users.
  [vladimirnani]

- Fixed Travis-PyPI release configuration.
  [jezdez]

- Make IP position argument optional.
  [aredalen]

- Added possibility to disable access log
  [svenhertle]

- Fix for IIS used as reverse proxy adding port number
  [Dmitri-Sintsov]

- Made the signal race condition safe.
  [Minkey27]

- Added AXES_ONLY_USER_FAILURES to support only looking at the user ID.
  [lip77us]


2.2.0 (2016-07-20)
------------------

- Improve the logic when using a reverse proxy to avoid possible attacks.
  [camilonova]


2.1.0 (2016-07-14)
------------------

- Add `default_app_config` so you can just use `axes` in `INSTALLED_APPS`
  [vdboor]


2.0.0 (2016-06-24)
------------------

- Removed middleware to use app_config
  [camilonova]

- Lots of cleaning
  [camilonova]

- Improved test suite and versions
  [camilonova]


1.7.0 (2016-06-10)
------------------

- Use render shortcut for rendering LOCKOUT_TEMPLATE
  [Radoslaw Luter]

- Added app_label for RemovedInDjango19Warning
  [yograterol]

- Add iso8601 translator.
  [mullakhmetov]

- Edit json response. Context now contains ISO 8601 formatted cooloff time
  [mullakhmetov]

- Add json response and iso8601 tests.
  [mullakhmetov]

- Fixes issue 162: UnicodeDecodeError on pip install
  [joeribekker]

- Added AXES_NEVER_LOCKOUT_WHITELIST option to prevent certain IPs from being locked out.
  [joeribekker]


1.6.1 (2016-05-13)
------------------

- Fixes whitelist check when BEHIND_REVERSE_PROXY
  [Patrick Hagemeister]

- Made migrations py3 compatible
  [mvdwaeter]

- Fixing #126, possibly breaking compatibility with Django<=1.7
  [int-ua]

- Add note for upgrading users about new migration files
  [kelseyq]

- Fixes #148
  [camilonova]

- Decorate auth_views.login only once
  [teeberg]

- Set IP public/private classifier to be compliant with RFC 1918.
  [SilasX]

- Issue #155. Lockout response status code changed to 403.
  [Arthur Mullahmetov]

- BUGFIX: Missing migration
  [smeinel]


1.6.0 (2016-01-07)
------------------

- Stopped using render_to_response so that other template engines work
  [tarkatronic]

- Improved performance & DoS prevention on query2str
  [tarkatronic]

- Immediately return from is_already_locked if the user is not lockable
  [jdunck]

- Iterate over ip addresses only once
  [annp89]

- added initial migration files to support django 1.7 &up. Upgrading users should run migrate --fake-initial after update
  [ibaguio]

- Add db indexes to CommonAccess model
  [Schweigi]


1.5.0 (2015-09-11)
------------------

- Fix #_get_user_attempts to include username when filtering AccessAttempts if AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP is True
  [afioca]


1.4.0 (2015-08-09)
------------------

- Send the user_locked_out signal. Fixes #94.
  [toabi]


1.3.9 (2015-02-11)
------------------

- Python 3 fix (#104)


1.3.8 (2014-10-07)
------------------

- Rename GitHub organization from django-security to django-pci to emphasize focus on providing assistance with building PCI compliant websites with Django.
  [aclark4life]


1.3.7 (2014-10-05)
------------------

- Explain common issues where Axes fails silently
  [cericoda]

- Allow for user-defined username field for lookup in POST data
  [SteveByerly]

- Log out only if user was logged in
  [zoten]

- Support for floats in cooloff time (i.e: 0.1 == 6 minutes)
  [marianov]

- Limit amount of POST data logged (#73). Limiting the length of value is not enough, as there could be arbitrary number of them, or very long key names.
  [peterkuma]

- Improve get_ip to try for real ip address
  [7wonders]

- Change IPAddressField to GenericIPAddressField. When using a PostgreSQL database and the client does not pass an IP address you get an inet error. This is a known problem with PostgreSQL and the IPAddressField. https://code.djangoproject.com/ticket/5622. It can be fixed by using a GenericIPAddressField instead.
  [polvoblanco]

- Get first X-Forwarded-For IP
  [tutumcloud]

- White listing IP addresses behind reverse proxy. Allowing some IP addresses to have direct access to the app even if they are behind a reverse proxy. Those IP addresses must still be on a white list.
  [ericbulloch]

- Reduce logging of reverse proxy IP lookup and use configured logger. Fixes #76. Instead of logging the notice that django.axes looks for a HTTP header set by a reverse proxy on each attempt, just log it one-time on first module import. Also use the configured logger (by default axes.watch_login) for the message to be more consistent in logging.
  [eht16]

- Limit the length of the values logged into the database. Refs #73
  [camilonova]

- Refactored tests to be more stable and faster
  [camilonova]

- Clean client references
  [camilonova]

- Fixed admin login url
  [camilonova]

- Added django 1.7 for testing
  [camilonova]

- Travis file cleanup
  [camilonova]

- Remove hardcoded url path
  [camilonova]

- Fixing tests for django 1.7
  [Andrew-Crosio]

- Fix for django 1.7 exception not existing
  [Andrew-Crosio]

- Removed python 2.6 from testing
  [camilonova]

- Use django built-in six version
  [camilonova]

- Added six as requirement
  [camilonova]

- Added python 2.6 for travis testing
  [camilonova]

- Replaced u string literal prefixes with six.u() calls
  [amrhassan]

- Fixes object type issue, response is not an string
  [camilonova]

- Python 3 compatibility fix for db_reset
  [nicois]

- Added example project and helper scripts
  [barseghyanartur]

- Admin command to list login attemps
  [marianov]

- Replaced six imports with django.utils.six ones
  [amrhassan]

- Replaced u string literal prefixes with six.u() calls to make it compatible with Python 3.2
  [amrhassan]

- Replaced `assertIn`s and `assertNotIn`s with `assertContains` and `assertNotContains`
  [fcurella]

- Added py3k to travis
  [fcurella]

- Update test cases to be python3 compatible
  [nicois]

- Python 3 compatibility fix for db_reset
  [nicois]

- Removed trash from example urls
  [barseghyanartur]

- Added django installer
  [barseghyanartur]

- Added example project and helper scripts
  [barseghyanartur]


1.3.6 (2013-11-23)
------------------

- Added AttributeError in case get_profile doesn't exist
  [camilonova]

- Improved axes_reset command
  [camilonova]


1.3.5 (2013-11-01)
------------------

- Fix an issue with __version__ loading the wrong version
  [graingert]


1.3.4 (2013-11-01)
------------------

- Update README.rst for PyPI
  [marty, camilonova, graingert]

- Add cooloff period
  [visualspace]


1.3.3 (2013-07-05)
------------------

- Added 'username' field to the Admin table
  [bkvirendra]

- Removed fallback logging creation since logging cames by default on django 1.4 or later,
  if you don't have it is because you explicitly wanted. Fixes #45
  [camilonova]


1.3.2 (2013-03-28)
------------------

- Fix an issue when a user logout
  [camilonova]

- Match pypi version
  [camilonova]

- Better User model import method
  [camilonova]

- Use only one place to get the version number
  [camilonova]

- Fixed an issue when a user on django 1.4 logout
  [camilonova]

- Handle exception if there is not user profile model set
  [camilonova]

- Made some cleanup and remove a pokemon exception handling
  [camilonova]

- Improved tests so it really looks for the rabbit in the hole
  [camilonova]

- Match pypi version
  [camilonova]


1.3.1 (2013-03-19)
------------------

- Add support for Django 1.5
  [camilonova]


1.3.0 (2013-02-27)
------------------

- Bug fix: get_version() format string
  [csghormley]


1.2.9 (2013-02-20)
------------------

- Add to and improve test cases
  [camilonova]


1.2.8 (2013-01-23)
------------------

- Increased http accept header length
  [jslatts]


1.2.7 (2013-01-17)
------------------

- Reverse proxy support
  [rmagee]

- Clean up README
  [martey]


1.2.6 (2012-12-04)
------------------

- Remove unused import
  [aclark4life]


1.2.5 (2012-11-28)
------------------

- Fix setup.py
  [aclark4life]

- Added ability to flag user accounts as unlockable.
  [kencochrane]

- Added ipaddress as a param to the user_locked_out signal.
  [kencochrane]

- Added a signal receiver for user_logged_out.
  [kencochrane]

- Added a signal for when a user gets locked out.
  [kencochrane]

- Added AccessLog model to log all access attempts.
  [kencochrane]
