import logging
import os
import unittest
from unittest.mock import patch

from fortigate_vpn_login import get_log_level


class GetLogLevelTest(unittest.TestCase):
    def test_normalizes_environment_value(self):
        with patch.dict(os.environ, {"LOG_LEVEL": " debug "}):
            level = get_log_level("FATAL")

        self.assertEqual(level, "DEBUG")
        test_logger = logging.getLogger("test-log-level")
        test_logger.setLevel(level)
        self.assertEqual(test_logger.level, logging.DEBUG)

    def test_uses_default_when_environment_value_is_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(get_log_level("INFO"), "INFO")


if __name__ == "__main__":
    unittest.main()
