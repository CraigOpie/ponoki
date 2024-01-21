# tests/test_ponoki.py

import unittest
from ponoki import PonoKi

class TestPasswordStrength(unittest.TestCase):
    """Group of tests to check password strength"""
    def test_strength_valid_password(self):
        self.assertTrue(PonoKi.check_password_strength('ValidPassword123!'))

    def test_strength_short_password(self):
        self.assertFalse(PonoKi.check_password_strength('short'))

    def test_strength_no_uppercase(self):
        self.assertFalse(PonoKi.check_password_strength('longbutnouppercase123!'))

    def test_strength_no_lowercase(self):
        self.assertFalse(PonoKi.check_password_strength('NOLOWERCASE123!'))

    def test_strength_no_number(self):
        self.assertFalse(PonoKi.check_password_strength('NoNumberSpecial!'))

    def test_strength_no_special_char(self):
        self.assertFalse(PonoKi.check_password_strength('NoSpecialCharacter123'))


class TestPasswordChange(unittest.TestCase):
    """Group of tests to check password change criteria"""


class TestPasswordCompromised(unittest.TestCase):
    """Group of tests to check if password is compromised"""


if __name__ == '__main__':
    unittest.main()