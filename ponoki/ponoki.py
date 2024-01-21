# ponoki.py

import requests
import re
import logging

class PonoKi:
    MIN_LENGTH = 15
    SPECIAL_CHARS = "~!@#$%^&*()-_"
    SPECIAL_CHARS_REGEX = re.compile("[" + re.escape(SPECIAL_CHARS) + "]")
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
            logging.warning("Password strength check failed: new password is less than 15 characters.")
            return False

        if (not re.search(r"[A-Z]", password) or
                not re.search(r"[a-z]", password) or
                not re.search(r"[0-9]", password) or
                not PonoKi.SPECIAL_CHARS_REGEX.search(password) or
                PonoKi.DISALLOWED_CHARS_REGEX.search(password) or
                ' ' in password):
            logging.warning("Password strength check failed: password must include one or more of the following special characters: ~!@#$%^&*()-_.")
            return False

        return True
    
    @staticmethod
    def password_is_shifted(old_password, new_password):
        """
        Check if a given password is a shifted version of another password.

        Args:
            old_password (str): The password to compare against.
            new_password (str): The password to check.

        Returns:
            bool: True if the new password is a shifted version of the old password, False otherwise.
        """
        lower_old = old_password.lower()
        for i in range(1, len(lower_old)):
            if lower_old[i:] + lower_old[:i] == new_password.lower():
                return True
        return False

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
        if not all(isinstance(pw, str) and pw for pw in [old_password, new_password]):
            logging.warning("Invalid input for password change check.")
            return False
        
        password_is_same = old_password == new_password
        if password_is_same:
            logging.warning("Password change check failed: new password is the same as the old password.")
            return False
        
        password_is_reversed = old_password[::-1].lower() == new_password.lower()
        if password_is_reversed:
            logging.warning("Password change check failed: new password is the reverse of the old password.")
            return False
        
        password_is_only_case_changed = old_password.lower() == new_password.lower()
        if password_is_only_case_changed:
            logging.warning("Password change check failed: new password is the same as the old password with only case changed.")
            return False

        half_length_of_password = len(set(new_password)) / 2
        number_of_different_chars = len(set(new_password).difference(set(old_password)))
        less_than_half_of_the_chars_changed = number_of_different_chars < half_length_of_password
        if less_than_half_of_the_chars_changed:
            logging.warning("Password change check failed: less than half of the characters are different.")
            return False
        
        if PonoKi.password_is_shifted(old_password, new_password):
            logging.warning("Password change check failed: new password is a shifted version of the old password.")
            return False
        
        return True

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