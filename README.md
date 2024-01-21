# PonoKi

PonoKi is a Python module designed to enhance password security. It provides functionalities to check if a password has been compromised, enforce strong password criteria, and ensure significant changes in new passwords.

## Features

- **Compromised Password Check**: Utilizes the "Have I Been Pwned" API to check if a password is part of any known data breaches.
- **Password Strength Validation**: Ensures passwords meet specific criteria, including minimum length, and contain uppercase, lowercase, numeric, and special characters.
- **Password Change Verification**: Validates that at least half of the characters in a new password are different from the old password.
- **Enhanced Error Handling and Logging**: Provides detailed error information and logging for better debugging and monitoring.

## Installation

To install PonoKi, you can use pip:

```bash
pip install ponoki
```

## Usage

Import the `PonoKi` class from the module and use its static methods to check passwords:

```python
from ponoki import PonoKi

# Check password strength and if it's compromised
password = "your_password_here"
status = PonoKi.check_password(password)
if status == PonoKi.PASSWORD_SAFE:
    print("Password is safe.")
elif status == PonoKi.PASSWORD_COMPROMISED:
    print("Password is compromised.")
elif status == PonoKi.PASSWORD_WEAK:
    print("Password is weak.")
else:
    print("Unable to determine password status.")

# Check if new password is sufficiently different from old password
old_password = "old_password_here"
new_password = "new_password_here"
if PonoKi.check_password_change(old_password, new_password):
    print("New password is sufficiently different.")
else:
    print("New password is too similar to the old password.")
```

## Unit Testing

PonoKi includes a comprehensive set of unit tests to ensure functionality and reliability. The tests can be found in `test_ponoki.py`` and cover various aspects of password checking and validation.

### Running Tests

To run the unit tests for PonoKi, execute the following command:

```bash
python -m unittest discover -s tests
```

### Coverage Reports

To generate a coverage report, execute the following command:

```bash
coverage html
```

## Dependencies

- `requests`

## License

This project is licensed under the Creative Commons Zero v1.0 Universal License - see the [LICENSE](LICENSE) file for details.