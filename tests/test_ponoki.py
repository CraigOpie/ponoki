# tests/test_ponoki.py

import pytest
import requests
from ponoki import PonoKi

class TestPasswordStrength:
    """Group of tests to check password strength"""
    def test_strength_valid_password(self):
        assert PonoKi.check_password_strength('ValidPassword123!')

    def test_strength_short_password(self):
        assert not PonoKi.check_password_strength('short')

    def test_strength_no_uppercase(self):
        assert not PonoKi.check_password_strength('longbutnouppercase123!')

    def test_strength_no_lowercase(self):
        assert not PonoKi.check_password_strength('NOLOWERCASE123!')

    def test_strength_no_number(self):
        assert not PonoKi.check_password_strength('NoNumberSpecial!')

    def test_strength_no_special_char(self):
        assert not PonoKi.check_password_strength('NoSpecialCharacter123')

    def test_strength_invalid_char(self):
        assert not PonoKi.check_password_strength('Invalid/Character123!')

    def test_strength_whitespace(self):
        assert not PonoKi.check_password_strength('Whitespace NotAllowed123!')


class TestPasswordChange:
    """Group of tests to check password change criteria"""
    def test_change_identical_passwords(self):
        assert not PonoKi.check_password_change('SamePassword123!', 'SamePassword123!')

    def test_change_reversed_password(self):
        assert not PonoKi.check_password_change('Password123!', '!321drowssaP')

    def test_change_case_only_changed(self):
        assert not PonoKi.check_password_change('CaseChange123!', 'casechange123!')

    def test_change_shifted_password(self):
        assert not PonoKi.check_password_change('Shifted123!', 'fted123!Shi')

    def test_change_insufficient_new_characters(self):
        assert not PonoKi.check_password_change('oldPassword123!', 'oldPassword123@')

    def test_change_sufficient_new_characters(self):
        assert PonoKi.check_password_change('oldPassword123!', 'newPa$$w0rd987@')


class TestPasswordCompromised:
    """Group of tests to check if password is compromised"""
    @pytest.mark.parametrize("mock_status, mock_text, expected_result", [
        (200, '1E4C9B93F3F0682250B6CF8331B7EE68FD8:2', 1),  # Compromised password
        (200, '', 0),   # Safe password
        (404, '', -1),  # API failure
    ])
    def test_password_compromised(self, mocker, mock_status, mock_text, expected_result):
        mock_get = mocker.patch('requests.get')
        mock_get.return_value.status_code = mock_status
        mock_get.return_value.text = mock_text

        assert PonoKi.check_password('password') == expected_result

    def test_network_exception(self, mocker):
        mocker.patch('requests.get', side_effect=requests.RequestException)
        assert PonoKi.check_password('password') == -1
