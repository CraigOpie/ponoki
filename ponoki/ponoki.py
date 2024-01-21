# ponoki.py

import requests
import re

class PonoKi:
    MIN_LENGTH = 15
    SPECIAL_CHARS = "~!@#$%^&*()-_"
    SPECIAL_CHARS_REGEX = re.compile("[" + SPECIAL_CHARS + "]")
    DISALLOWED_CHARS_REGEX = re.compile(r"[+=\[\]\/?><,;:\'\"\\|`]")

    @staticmethod
    def check_password_strength(password):
        """
        Check the strength of a given password based on length and character composition.

        Args:
            password (str): The password to check.

        Returns:
            bool: True if the password meets the criteria, False otherwise.
        """
        if len(password) < PonoKi.MIN_LENGTH:
            return False

        if (not re.search(r"[A-Z]", password) or
                not re.search(r"[a-z]", password) or
                not re.search(r"[0-9]", password) or
                not PonoKi.SPECIAL_CHARS_REGEX.search(password) or
                PonoKi.DISALLOWED_CHARS_REGEX.search(password) or
                ' ' in password):
            return False

        return True

    @staticmethod
    def check_password_change(old_password, new_password):
        """
        Check that at least half of the characters in the new password are different from the old password.

        Args:
            old_password (str): The user's old password.
            new_password (str): The user's new password.

        Returns:
            bool: True if at least half of the characters are different, False otherwise.
        """

    @staticmethod
    def check_password(password):
        """
        Check if a given password has been compromised and meets strength criteria.

        Args:
            password (str): The password to check.

        Returns:
            int: PASSWORD_SAFE for a good and strong password, PASSWORD_COMPROMISED for a compromised password,
                 PASSWORD_WEAK for a weak password, STATUS_UNDETERMINED for unable to determine.
        """