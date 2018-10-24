from django.test import TestCase


class MigrationsCheck(TestCase):
    def setUp(self):
        from django.utils import translation
        self.saved_locale = translation.get_language()
        translation.deactivate_all()

    def tearDown(self):
        if self.saved_locale is not None:
            from django.utils import translation
            translation.activate(self.saved_locale)

    def test_missing_migrations(self):
        from django.db import connection
        from django.apps.registry import apps
        from django.db.migrations.executor import MigrationExecutor
        executor = MigrationExecutor(connection)
        from django.db.migrations.autodetector import MigrationAutodetector
        from django.db.migrations.state import ProjectState
        autodetector = MigrationAutodetector(
            executor.loader.project_state(),
            ProjectState.from_apps(apps),
        )
        changes = autodetector.changes(graph=executor.loader.graph)
        self.assertEqual({}, changes)
