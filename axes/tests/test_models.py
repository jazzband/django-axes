from django.apps.registry import apps
from django.db import connection
from django.db.migrations.autodetector import MigrationAutodetector
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.state import ProjectState
from django.test import TestCase
from django.utils import translation


class MigrationsCheck(TestCase):
    def setUp(self):
        self.saved_locale = translation.get_language()
        translation.deactivate_all()

    def tearDown(self):
        if self.saved_locale is not None:
            translation.activate(self.saved_locale)

    def test_missing_migrations(self):
        executor = MigrationExecutor(connection)
        autodetector = MigrationAutodetector(
            executor.loader.project_state(),
            ProjectState.from_apps(apps),
        )

        changes = autodetector.changes(graph=executor.loader.graph)

        self.assertEqual({}, changes)
