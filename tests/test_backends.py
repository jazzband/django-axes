from unittest.mock import patch, MagicMock

from axes.backends import AxesBackend
from axes.exceptions import (
    AxesBackendRequestParameterRequired,
    AxesBackendPermissionDenied,
)
from tests.base import AxesTestCase


class BackendTestCase(AxesTestCase):
    def test_authenticate_raises_on_missing_request(self):
        request = None

        with self.assertRaises(AxesBackendRequestParameterRequired):
            AxesBackend().authenticate(request)

    @patch("axes.handlers.proxy.AxesProxyHandler.is_allowed", return_value=False)
    def test_authenticate_raises_on_locked_request(self, _):
        request = MagicMock()

        with self.assertRaises(AxesBackendPermissionDenied):
            AxesBackend().authenticate(request)
