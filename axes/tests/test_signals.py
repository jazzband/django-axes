from unittest.mock import MagicMock

from axes.tests.base import AxesTestCase
from axes.signals import user_locked_out


class SignalTestCase(AxesTestCase):
    def test_send_lockout_signal(self):
        """
        Test if the lockout signal is correctly emitted when user is locked out.
        """

        handler = MagicMock()
        user_locked_out.connect(handler)

        self.assertEqual(0, handler.call_count)
        self.lockout()
        self.assertEqual(1, handler.call_count)
