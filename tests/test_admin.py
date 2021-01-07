from contextlib import suppress
from importlib import reload

from django.contrib import admin
from django.test import override_settings

import axes.admin
from axes.models import AccessAttempt, AccessLog
from tests.base import AxesTestCase


class AxesEnableAdminFlag(AxesTestCase):
    def setUp(self):
        with suppress(admin.sites.NotRegistered):
            admin.site.unregister(AccessAttempt)
        with suppress(admin.sites.NotRegistered):
            admin.site.unregister(AccessLog)

    @override_settings(AXES_ENABLE_ADMIN=False)
    def test_disable_admin(self):
        reload(axes.admin)
        self.assertFalse(admin.site.is_registered(AccessAttempt))
        self.assertFalse(admin.site.is_registered(AccessLog))

    def test_enable_admin_by_default(self):
        reload(axes.admin)
        self.assertTrue(admin.site.is_registered(AccessAttempt))
        self.assertTrue(admin.site.is_registered(AccessLog))
