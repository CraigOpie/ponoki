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

    def test_strength_invalid_char(self):
        self.assertFalse(PonoKi.check_password_strength('Invalid/Character123!'))

    def test_strength_whitespace(self):
        self.assertFalse(PonoKi.check_password_strength('Whitespace NotAllowed123!'))


class TestPasswordChange(unittest.TestCase):
    """Group of tests to check password change criteria"""
    def test_change_significant_difference(self):
        self.assertTrue(PonoKi.check_password_change('oldPassword123!', 'newPassword987@'))

    def test_change_insufficient_difference(self):
        self.assertFalse(PonoKi.check_password_change('oldPassword123!', 'oldPassword1234!'))


class TestPasswordCompromised(unittest.TestCase):
    """Group of tests to check if password is compromised"""


if __name__ == '__main__':
    unittest.main()