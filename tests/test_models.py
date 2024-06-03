from django.apps.registry import apps
from django.db import connection
from django.db.migrations.autodetector import MigrationAutodetector
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.state import ProjectState

from axes.models import AccessAttempt, AccessLog, AccessFailureLog
from tests.base import AxesTestCase


class ModelsTestCase(AxesTestCase):
    def setUp(self):
        self.failures_since_start = 42

        self.access_attempt = AccessAttempt(
            failures_since_start=self.failures_since_start
        )
        self.access_log = AccessLog()
        self.access_failure_log = AccessFailureLog()

    def test_access_attempt_str(self):
        self.assertIn("Access", str(self.access_attempt))

    def test_access_log_str(self):
        self.assertIn("Access", str(self.access_log))

    def test_access_failure_log_str(self):
        self.assertIn("Failed", str(self.access_failure_log))


class MigrationsTestCase(AxesTestCase):
    def test_missing_migrations(self):
        executor = MigrationExecutor(connection)
        autodetector = MigrationAutodetector(
            executor.loader.project_state(), ProjectState.from_apps(apps)
        )

        changes = autodetector.changes(graph=executor.loader.graph)

        self.assertEqual({}, changes)
