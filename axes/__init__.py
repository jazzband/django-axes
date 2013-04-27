import os
import logging


VERSION = (1, 3, 2)


def get_version():
    return '%s.%s.%s' % VERSION

try:
    # check for existing logging configuration
    # valid for Django>=1.3
    from django.conf import settings
    if settings.LOGGING:
        pass
except ImportError:
    # if we have any problems, we most likely don't have a settings module
    # loaded
    pass
except AttributeError:
    # fallback configuration if there is no logging configuration
    LOGFILE = os.path.join(settings.DIRNAME, 'axes.log')

    log_format = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        format=log_format,
                        datefmt='%a, %d %b %Y %H:%M:%S',
                        filename=LOGFILE,
                        filemode='w')

    fileLog = logging.FileHandler(LOGFILE, 'w')
    fileLog.setLevel(logging.DEBUG)

    # set a format which is simpler for console use
    console_format = '%(asctime)s %(name)-12s: %(levelname)-8s %(message)s'
    formatter = logging.Formatter(console_format)

    # tell the handler to use this format
    fileLog.setFormatter(formatter)

    # add the handler to the root logger
    logging.getLogger('').addHandler(fileLog)
