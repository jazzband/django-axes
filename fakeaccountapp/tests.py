import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from .backup import create_secure_backup, decrypt_secure_backup
from .forms import RegistrationForm
from .models import LoginLog
from .network import get_private_ip_addresses
from .signals import get_client_ip


User = get_user_model()


class RegistrationTests(TestCase):
    def test_register_creates_user_with_hashed_password(self):
        response = self.client.post(
            reverse("register"),
            {"username": "jan", "password": "StrongPass123"},
            REMOTE_ADDR="127.0.0.1",
        )

        self.assertRedirects(response, reverse("login"))
        user = User.objects.get(username="jan")
        self.assertTrue(user.check_password("StrongPass123"))
        self.assertTrue(LoginLog.objects.filter(user=user, ip_address="127.0.0.1").exists())

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://127.0.0.1:8000"])
    def test_register_accepts_https_origin_with_csrf_checks(self):
        client = self.client_class(enforce_csrf_checks=True)
        get_response = client.get(reverse("register"), secure=True, SERVER_NAME="127.0.0.1", SERVER_PORT=8000)
        csrf_token = get_response.cookies["csrftoken"].value

        response = client.post(
            reverse("register"),
            {"username": "https-user", "password": "StrongPass123", "csrfmiddlewaretoken": csrf_token},
            secure=True,
            SERVER_NAME="127.0.0.1",
            SERVER_PORT=8000,
            HTTP_ORIGIN="https://127.0.0.1:8000",
        )

        self.assertRedirects(response, reverse("login"))
        self.assertTrue(User.objects.filter(username="https-user").exists())

    def test_registration_rejects_similar_username(self):
        User.objects.create_user(username="admin", password="pass")

        form = RegistrationForm({"username": "adm1n", "password": "StrongPass123"})

        self.assertFalse(form.is_valid())
        self.assertIn("username", form.errors)


class ReactStaticAssetTests(TestCase):
    def test_react_javascript_build_is_served_as_a_javascript_module(self):
        response = self.client.get("/static/react/assets/app.js")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/javascript")


class LoginIpSignalTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="anna", password="StrongPass123")

    def test_get_client_ip_prefers_forwarded_for_first_ip(self):
        request = type(
            "Request",
            (),
            {"META": {"HTTP_X_FORWARDED_FOR": "10.0.0.2, 10.0.0.3", "REMOTE_ADDR": "127.0.0.1"}},
        )()

        self.assertEqual(get_client_ip(request), "10.0.0.2")

    @patch("fakeaccountapp.signals.create_secure_backup")
    def test_login_from_different_ip_after_registration_creates_backup(self, create_backup):
        self.client.post(
            reverse("register"),
            {"username": "marek", "password": "StrongPass123"},
            REMOTE_ADDR="127.0.0.1",
        )
        self.client.post(
            reverse("login"),
            {"username": "marek", "password": "StrongPass123"},
            REMOTE_ADDR="10.0.0.5",
        )

        user = User.objects.get(username="marek")
        self.assertEqual(LoginLog.objects.filter(user=user).count(), 2)
        create_backup.assert_called_once_with(skip_duplicate=True)

    @patch("fakeaccountapp.signals.create_secure_backup")
    def test_login_from_same_ip_after_registration_does_not_create_backup(self, create_backup):
        self.client.post(
            reverse("register"),
            {"username": "ewa", "password": "StrongPass123"},
            REMOTE_ADDR="127.0.0.1",
        )
        self.client.post(
            reverse("login"),
            {"username": "ewa", "password": "StrongPass123"},
            REMOTE_ADDR="127.0.0.1",
        )

        create_backup.assert_not_called()


class LogoutTests(TestCase):
    def test_logout_accepts_get_request(self):
        User.objects.create_user(username="logout-user", password="StrongPass123")
        self.client.login(username="logout-user", password="StrongPass123")

        response = self.client.get(reverse("logout"))

        self.assertRedirects(response, "/login/")


class NetworkConfigTests(TestCase):
    @patch("fakeaccountapp.network.socket.getaddrinfo")
    @patch("fakeaccountapp.network.socket.socket")
    def test_private_ip_detection_ignores_loopback_and_link_local(self, socket_class, getaddrinfo):
        getaddrinfo.return_value = [
            (None, None, None, None, ("127.0.0.1", 0)),
            (None, None, None, None, ("169.254.1.1", 0)),
            (None, None, None, None, ("192.168.1.22", 0)),
        ]
        socket_class.side_effect = OSError

        self.assertEqual(get_private_ip_addresses(), ["192.168.1.22"])


class AdminBackupDownloadTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            username="staff",
            password="StrongPass123",
            is_staff=True,
        )

    @patch("fakeaccountapp.views.decrypt_secure_backup", return_value=b'[{"model": "auth.user"}]')
    def test_staff_can_download_decrypted_backup(self, decrypt_backup):
        self.client.login(username="staff", password="StrongPass123")

        response = self.client.get(reverse("download_decrypted_backup"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("backup.json", response["Content-Disposition"])
        self.assertEqual(response.content, b'[{"model": "auth.user"}]')
        decrypt_backup.assert_called_once_with()

    def test_anonymous_user_is_redirected_from_backup_download(self):
        response = self.client.get(reverse("download_decrypted_backup"))

        self.assertEqual(response.status_code, 302)


@override_settings(SECURE_BACKUP_DIR=Path(tempfile.gettempdir()) / "fakeaccount-test-backups")
class SecureBackupIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if importlib.util.find_spec("cryptography") is None:
            raise unittest.SkipTest("cryptography is not installed")

    def test_backup_encrypts_decrypts_and_skips_duplicate_dump(self):
        User.objects.create_user(username="backup-user", password="StrongPass123")

        first = create_secure_backup(skip_duplicate=True)
        second = create_secure_backup(skip_duplicate=True)
        decrypted = decrypt_secure_backup()

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertIn(b"backup-user", decrypted)
