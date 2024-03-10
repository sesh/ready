from unittest import TestCase

from ready.checks.cookies import (
    check_cookies_should_be_samesite,
    check_cookies_should_be_secure,
    check_cookies_should_be_httponly,
)
from ready.thttp import Response


# logged_in=no; Path=/; Domain=github.com; Expires=Mon, 10 Mar 2025 21:34:03 GMT; HttpOnly; Secure; SameSite=Lax


class ContentChecksTestCase(TestCase):
    def test_check_cookies_should_be_samesite(self):
        r = Response(None, "", None, 200, None, {}, None)
        result = check_cookies_should_be_samesite({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"set-cookie": "admin=no; Path=/; Domain=ready.invalid; SameSite=Lax"}, None)
        result = check_cookies_should_be_samesite({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"set-cookie": "admin=no; Path=/; Domain=ready.invalid"}, None)
        result = check_cookies_should_be_samesite({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_cookies_should_be_secure(self):
        r = Response(None, "", None, 200, None, {}, None)
        result = check_cookies_should_be_secure({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"set-cookie": "admin=no; Path=/; Domain=ready.invalid; Secure;"}, None)
        result = check_cookies_should_be_secure({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"set-cookie": "admin=no; Path=/; Domain=ready.invalid;"}, None)
        result = check_cookies_should_be_secure({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_cookies_should_be_httponly(self):
        r = Response(None, "", None, 200, None, {}, None)
        result = check_cookies_should_be_httponly({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"set-cookie": "admin=no; Path=/; Domain=ready.invalid; HttpOnly;"}, None)
        result = check_cookies_should_be_httponly({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"set-cookie": "admin=no; Path=/; Domain=ready.invalid;"}, None)
        result = check_cookies_should_be_httponly({"response": r}, print_output=False)
        self.assertFalse(result.passed)
