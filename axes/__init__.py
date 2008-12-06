VERSION = (0, 1, 1, 'rc1')

def get_version():
    return '%s.%s.%s-%s' % VERSION

try:
    from django.conf import settings
    import logging, os

    LOGFILE = os.path.join(settings.DIRNAME, 'axes.log')
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                        datefmt='%a, %d %b %Y %H:%M:%S',
                        filename=LOGFILE,
                        filemode='w')

    fileLog = logging.FileHandler(LOGFILE, 'w')
    fileLog.setLevel(logging.DEBUG)

    # set a format which is simpler for console use
    formatter = logging.Formatter('%(asctime)s %(name)-12s: %(levelname)-8s %(message)s')

    # tell the handler to use this format
    fileLog.setFormatter(formatter)

    # add the handler to the root logger
    logging.getLogger('').addHandler(fileLog)
except:
    # if we have any problems, we most likely don't have a settings module loaded
    pass