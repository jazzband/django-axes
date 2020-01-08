.. _configuration:

Configuration
=============

Minimal Axes configuration is done with just ``settings.py`` updates.

More advanced configuration and integrations might require updates
on source code level depending on your project implementation.


Configuring project settings
----------------------------

The following ``settings.py`` options are available for customizing Axes behaviour.

* ``AXES_ENABLED``: Enable or disable Axes plugin functionality,
  for example in test runner setup. Default: ``True``
* ``AXES_FAILURE_LIMIT``: The integer number of login attempts allowed before a
  record is created for the failed logins. This can also be a callable
  or a dotted path to callable that returns an integer and all of the following are valid:
  ``AXES_FAILURE_LIMIT = 42``,
  ``AXES_FAILURE_LIMIT = lambda *args: 42``, and
  ``AXES_FAILURE_LIMIT = 'project.app.get_login_failure_limit'``.
  Default: ``3``
* ``AXES_LOCK_OUT_AT_FAILURE``: After the number of allowed login attempts
  are exceeded, should we lock out this IP (and optional user agent)?
  Default: ``True``
* ``AXES_COOLOFF_TIME``: If set, defines a period of inactivity after which
  old failed login attempts will be cleared.
  Can be set to a Python timedelta object, an integer, a callable,
  or a string path to a callable which takes no arguments.
  If an integer, will be interpreted as a number of hours.
  Default: ``None``
* ``AXES_ONLY_ADMIN_SITE`` : If ``True``, lock is only enable for admin site,
  Default: ``False``
* ``AXES_ONLY_USER_FAILURES`` : If ``True``, only lock based on username,
  and never lock based on IP if attempts exceed the limit.
  Otherwise utilize the existing IP and user locking logic.
  Default: ``False``
* ``AXES_ENABLE_ADMIN``: If ``True``, admin views for access attempts and
  logins are shown in Django admin interface.
  Default: ``True``
* ``AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP``: If ``True``, prevent login
  from IP under a particular username if the attempt limit has been exceeded,
  otherwise lock out based on IP.
  Default: ``False``
* ``AXES_USE_USER_AGENT``: If ``True``, lock out and log based on the IP address
  and the user agent.  This means requests from different user agents but from
  the same IP are treated differently. This settings has no effect if the
  ``AXES_ONLY_USER_FAILURES`` setting is active.
  Default: ``False``
* ``AXES_LOGGER``: If set, specifies a logging mechanism for Axes to use.
  Default: ``'axes.watch_login'``
* ``AXES_HANDLER``: The path to the handler class to use.
  If set, overrides the default signal handler backend.
  Default: ``'axes.handlers.database.DatabaseHandler'``
* ``AXES_CACHE``: The name of the cache for Axes to use.
  Default: ``'default'``
* ``AXES_LOCKOUT_TEMPLATE``: If set, specifies a template to render when a
  user is locked out. Template receives ``cooloff_time`` and ``failure_limit`` as
  context variables.
  Default: ``None``
* ``AXES_LOCKOUT_URL``: If set, specifies a URL to redirect to on lockout. If both
  ``AXES_LOCKOUT_TEMPLATE`` and ``AXES_LOCKOUT_URL`` are set, the template will be used.
  Default: ``None``
* ``AXES_VERBOSE``: If ``True``, you'll see slightly more logging for Axes.
  Default: ``True``
* ``AXES_USERNAME_FORM_FIELD``: the name of the form field that contains your users usernames.
  Default: ``username``
* ``AXES_USERNAME_CALLABLE``: A callable or a string path to callable that takes
  two arguments for user lookups: ``def get_username(request: HttpRequest, credentials: dict) -> str: ...``.
  This can be any callable such as ``AXES_USERNAME_CALLABLE = lambda request, credentials: 'username'``
  or a full Python module path to callable such as ``AXES_USERNAME_CALLABLE = 'example.get_username``.
  The ``request`` is a HttpRequest like object and the ``credentials`` is a dictionary like object.
  ``credentials`` are the ones that were passed to Django ``authenticate()`` in the login flow.
  If no function is supplied, Axes fetches the username from the ``credentials`` or ``request.POST``
  dictionaries based on ``AXES_USERNAME_FORM_FIELD``.
* ``AXES_WHITELIST_CALLABLE``: A callable or a string path to callable that takes
  two arguments for whitelisting determination and returns True,
  if user should be whitelisted:
  ``def is_whilisted(request: HttpRequest, credentials: dict) -> bool: ...``.
  This can be any callable similarly to ``AXES_USERNAME_CALLABLE``.
  Default: ``None``
* ``AXES_LOCKOUT_CALLABLE``: A callable or a string path to callable that takes
  two arguments returns a response. For example:
  ``def generate_lockout_response(request: HttpRequest, credentials: dict) -> HttpResponse: ...``.
  This can be any callable similarly to ``AXES_USERNAME_CALLABLE``.
  If not callable is defined, then the default implementation in ``axes.helpers.get_lockout_response``
  is used for determining the correct lockout response that is sent to the requesting client.
  Default: ``None``
* ``AXES_PASSWORD_FORM_FIELD``: the name of the form or credentials field that contains your users password.
  Default: ``password``
* ``AXES_NEVER_LOCKOUT_GET``: If ``True``, Axes will never lock out HTTP GET requests.
  Default: ``False``
* ``AXES_NEVER_LOCKOUT_WHITELIST``: If ``True``, users can always login from whitelisted IP addresses.
  Default: ``False``
* ``AXES_IP_BLACKLIST``: An iterable of IPs to be blacklisted.
  Takes precedence over whitelists. For example: ``AXES_IP_BLACKLIST = ['0.0.0.0']``.
  Default: ``None``
* ``AXES_IP_WHITELIST``: An iterable of IPs to be whitelisted.
  For example: ``AXES_IP_WHITELIST = ['0.0.0.0']``.
  Default: ``None``
* ``AXES_DISABLE_ACCESS_LOG``: If ``True``, disable writing login and logout access logs to database,
  so the admin interface will not have user login trail for successful user authentication.
  Default: ``False``
* ``AXES_RESET_ON_SUCCESS``: If ``True``, a successful login will reset the number of failed logins.
  Default: ``False``

The configuration option precedences for the access attempt monitoring are:

1. Default: only use IP address.
2. ``AXES_ONLY_USER_FAILURES``: only user username (``AXES_USE_USER_AGENT`` has no effect).
3. ``AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP``: use username and IP address.

The ``AXES_USE_USER_AGENT`` setting can be used with username and IP address or just IP address monitoring,
but does nothing when the ``AXES_ONLY_USER_FAILURES`` setting is set.


Configuring reverse proxies
---------------------------

Axes makes use of ``django-ipware`` package to detect the IP address of the client
and uses some conservative configuration parameters by default for security.

If you are using reverse proxies, you will need to configure one or more of the
following settings to suit your set up to correctly resolve client IP addresses:

* ``AXES_PROXY_COUNT``: The number of reverse proxies in front of Django as an integer. Default: ``None``
* ``AXES_META_PRECEDENCE_ORDER``: The names of ``request.META`` attributes as a tuple of strings
  to check to get the client IP address. Check the Django documentation for header naming conventions.
  Default: ``IPWARE_META_PRECEDENCE_ORDER`` setting if set, else ``('REMOTE_ADDR', )``

.. note::
   For reverse proxies or e.g. Heroku, you might also want to fetch IP addresses from a HTTP header such as ``X-Forwarded-For``. To configure this, you can fetch IPs through the ``HTTP_X_FORWARDED_FOR`` key from the ``request.META`` property which contains all the HTTP headers in Django:

   .. code-block:: python

      # refer to the Django request and response objects documentation
      AXES_META_PRECEDENCE_ORDER = [
         'HTTP_X_FORWARDED_FOR',
         'REMOTE_ADDR',
      ]

   Please note that proxies have different behaviours with the HTTP headers. Make sure that your proxy either strips the incoming value or otherwise makes sure of the validity of the header that is used because **any header values used in application configuration must be secure and trusted**. Otherwise the client can spoof IP addresses by just setting the header in their request and circumvent the IP address monitoring. Normal proxy server behaviours include overriding and appending the header value depending on the platform. Different platforms and gateway services utilize different headers, please refer to your deployment target documentation for up-to-date information on correct configuration.


Configuring handlers
--------------------

Axes uses handlers for processing signals and events
from Django authentication and login attempts.

The following handlers are implemented by Axes and can be configured
with the ``AXES_HANDLER`` setting in project configuration:

- ``axes.handlers.database.AxesDatabaseHandler``
  logs attempts to database and creates AccessAttempt and AccessLog records
  that persist until removed from the database manually or automatically
  after their cool offs expire (checked on each login event).
- ``axes.handlers.cache.AxesCacheHandler``
  only uses the cache for monitoring attempts and does not persist data
  other than in the cache backend; this data can be purged automatically
  depending on your cache configuration, so the cache handler is by design
  less secure than the database backend but offers higher throughput
  and can perform better with less bottlenecks.
  The cache backend should ideally be used with a central cache system
  such as a Memcached cache and should not rely on individual server
  state such as the local memory or file based cache does.
- ``axes.handlers.dummy.AxesDummyHandler``
  does nothing with attempts and can be used to disable Axes handlers
  if the user does not wish Axes to execute any logic on login signals.
  Please note that this effectively disables any Axes security features,
  and is meant to be used on e.g. local development setups
  and testing deployments where login monitoring is not wanted.

To switch to cache based attempt tracking you can do the following::

    AXES_HANDLER = 'axes.handlers.cache.AxesCacheHandler'

See the cache configuration section for suitable cache backends.


Configuring caches
------------------

If you are running Axes with the cache based handler on a deployment with a
local Django cache, the Axes lockout and reset functionality might not work
predictably if the cache in use is not the same for all the Django processes.

Axes needs to cache access attempts application-wide, and e.g. the
in-memory cache only caches access attempts per Django process, so for example
resets made in the command line might not remove lock-outs that are in a separate
process's in-memory cache such as the web server serving your login or admin page.

To circumvent this problem, please use somethings else than
``django.core.cache.backends.dummy.DummyCache``,
``django.core.cache.backends.locmem.LocMemCache``, or
``django.core.cache.backends.filebased.FileBasedCache``
as your cache backend in Django cache ``BACKEND`` setting.

If changing the ``'default'`` cache is not an option, you can add a cache
specifically for use with Axes. This is a two step process. First you need to
add an extra cache to ``CACHES`` with a name of your choice::

    CACHES = {
        'axes': {
            'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
            'LOCATION': '127.0.0.1:11211',
        }
    }

The next step is to tell Axes to use this cache through adding ``AXES_CACHE``
to your ``settings.py`` file::

    AXES_CACHE = 'axes'

There are no known problems in e.g. ``MemcachedCache`` or Redis based caches.


Configuring authentication backends
-----------------------------------

Axes requires authentication backends to pass request objects
with the authentication requests for performing monitoring.

If you get ``AxesBackendRequestParameterRequired`` exceptions,
make sure any libraries and middleware you use pass the request object.

Please check the integration documentation for further information.


Configuring 3rd party apps
--------------------------

Refer to the integration documentation for Axes configuration
with third party applications and plugins such as

- Django REST Framework
- Django Allauth
- Django Simple Captcha
