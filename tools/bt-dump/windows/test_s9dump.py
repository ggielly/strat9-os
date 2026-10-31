"""Tests for the Windows error diagnostics (no BLE, no bleak)."""

import unittest

from s9dump import _win_error_code, win_error_hint


class _WinError(Exception):
    def __init__(self, winerror):
        super().__init__("fake")
        self.winerror = winerror


class WinErrorTests(unittest.TestCase):
    def test_service_disabled_signed_hresult(self):
        exc = _WinError(-2147023838)  # 0x80070422
        self.assertEqual(_win_error_code(exc), 0x80070422)
        hint = win_error_hint(exc)
        self.assertIsNotNone(hint)
        self.assertIn("Bluetooth Support Service", hint)

    def test_service_disabled_unsigned_win32(self):
        hint = win_error_hint(_WinError(1058))
        self.assertIsNotNone(hint)
        self.assertIn("bthserv", hint)

    def test_unknown_error_has_no_hint(self):
        self.assertIsNone(win_error_hint(_WinError(2)))
        self.assertIsNone(win_error_hint(OSError(2, "not found")))

    def test_non_windows_error(self):
        self.assertIsNone(_win_error_code(ValueError("x")))
        self.assertIsNone(win_error_hint(ValueError("x")))


if __name__ == "__main__":
    unittest.main()
