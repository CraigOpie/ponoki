# ponoki.py

import hashlib
import requests
import re
import logging

class PonoKi:
    MIN_LENGTH = 15
    SPECIAL_CHARS = "~!@#$%^&*()-_"
    SPECIAL_CHARS_REGEX = re.compile("[" + re.escape(SPECIAL_CHARS) + "]")
    DISALLOWED_CHARS_REGEX = re.compile(r"[+=\[\]\/?><,;:\'\"\\|`]")
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
    PASSWORD_SAFE = 0
    PASSWORD_COMPROMISED = 1
    PASSWORD_WEAK = 2
    STATUS_UNDETERMINED = -1

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
        Check if a given password has been compromised.

        Args:
            password (str): The password to check.

        Returns:
            int: PASSWORD_SAFE for a good and strong password, PASSWORD_COMPROMISED for a compromised password,
                STATUS_UNDETERMINED for unable to determine.
        """
        if not isinstance(password, str) or not password:
            logging.warning("Invalid input for password check.")
            return PonoKi.STATUS_UNDETERMINED

        try:
            # Create a SHA-1 hash of the password
            hash_object = hashlib.sha1(password.encode('utf-8'))
            hashed_password = hash_object.hexdigest().upper()

            # Extract the first 5 characters as a prefix
            prefix = hashed_password[:5]
            suffix = hashed_password[5:]

            # Call the API with the prefix
            response = requests.get(PonoKi.HIBP_API_URL + prefix)

            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, _ in hashes:
                    if h.startswith(suffix):
                        return PonoKi.PASSWORD_COMPROMISED
                return PonoKi.PASSWORD_SAFE
            elif 400 <= response.status_code < 500:
                logging.error(f"Client error: {response.status_code}")
                return PonoKi.STATUS_UNDETERMINED
            elif 500 <= response.status_code:
                logging.error(f"Server error: {response.status_code}")
                return PonoKi.STATUS_UNDETERMINED
            else:
                logging.warning(f"Unexpected status code: {response.status_code}")
                return PonoKi.STATUS_UNDETERMINED
        except requests.Timeout:
            logging.error("Request timeout")
            return PonoKi.STATUS_UNDETERMINED
        except requests.ConnectionError:
            logging.error("Connection error")
            return PonoKi.STATUS_UNDETERMINED
        except requests.RequestException as e:
            logging.error(f"Request exception: {e}")
            return PonoKi.STATUS_UNDETERMINED
            