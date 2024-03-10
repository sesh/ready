from unittest import TestCase
from datetime import timedelta
from ready.checks.well_known import (
    check_robots_txt_exists,
    check_security_txt_exists,
    check_security_txt_not_expired,
    check_favicon_is_served,
    get_utc_time,
)
from ready.thttp import Response


class WellKnownChecksTestCase(TestCase):
    def test_check_robots_txt_exists(self):
        r = Response(None, b"", None, 200, None, {"content-type": "text/plain"}, None)
        result = check_robots_txt_exists({"robots_txt_response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"", None, 404, None, {}, None)
        result = check_robots_txt_exists({"robots_txt_response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_security_txt_exists(self):
        # Test with valid security.txt response
        security_response = Response(
            None,
            b"Contact: security@ready.invalid\nExpires: 2030-12-31T00:00:00Z",
            None,
            200,
            None,
            {"content-type": "text/plain"},
            None,
        )
        result = check_security_txt_exists({"security_txt_response": security_response}, print_output=False)
        self.assertTrue(result.passed)

        # Test with None security.txt response
        result = check_security_txt_exists({"security_txt_response": None}, print_output=False)
        self.assertFalse(result.passed)

        # Test with non-200 status code
        security_response = Response(None, b"", None, 404, None, {"content-type": "text/plain"}, None)
        result = check_security_txt_exists({"security_txt_response": security_response}, print_output=False)
        self.assertFalse(result.passed)

        # Test with incorrect content-type
        security_response = Response(None, b"", None, 200, None, {"content-type": "application/json"}, None)
        result = check_security_txt_exists({"security_txt_response": security_response}, print_output=False)
        self.assertFalse(result.passed)

        # Test with missing required attributes
        security_response = Response(
            None, b"Contact: security@ready.invalid", None, 200, None, {"content-type": "text/plain"}, None
        )
        result = check_security_txt_exists({"security_txt_response": security_response}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_favicon_is_served(self):
        # Test with valid favicon response
        favicon_response = Response(None, b"", None, 200, None, {"content-type": "image/x-icon"}, None)
        result = check_favicon_is_served({"favicon_response": favicon_response}, print_output=False)
        self.assertTrue(result.passed)

        # Test with invalid content-type
        favicon_response = Response(None, b"", None, 200, None, {"content-type": "text/html"}, None)
        result = check_favicon_is_served({"favicon_response": favicon_response}, print_output=False)
        self.assertFalse(result.passed)

        # Test with non-200 status code
        favicon_response = Response(None, b"", None, 404, None, {}, None)
        result = check_favicon_is_served({"favicon_response": favicon_response}, print_output=False)
        self.assertFalse(result.passed)

        # Test with None response
        result = check_favicon_is_served({"favicon_response": None}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_security_txt_not_expired(self):
        # Test with valid future expiry date
        future_date = get_utc_time() + timedelta(days=30)
        content = f"Expires: {future_date.isoformat()}\n".encode()
        security_response = Response(None, content, None, 200, {"content-type": "text/plain"}, {}, None)
        result = check_security_txt_not_expired({"security_txt_response": security_response}, print_output=False)
        self.assertTrue(result.passed)

        content = f"Expires: 2030-12-31T00:00:00Z\n".encode()
        security_response = Response(None, content, None, 200, {"content-type": "text/plain"}, {}, None)
        result = check_security_txt_not_expired({"security_txt_response": security_response}, print_output=False)
        self.assertTrue(result.passed)

        content = f"Expires: Not a date\n".encode()
        security_response = Response(None, content, None, 200, {"content-type": "text/plain"}, {}, None)
        result = check_security_txt_not_expired({"security_txt_response": security_response}, print_output=False)
        self.assertFalse(result.passed)

        # Test with expired expiry date
        past_date = get_utc_time() - timedelta(days=30)
        content = f"Expires: {past_date.isoformat()}\n".encode()
        security_response = Response(None, content, None, 200, {"content-type": "text/plain"}, {}, None)
        result = check_security_txt_not_expired({"security_txt_response": security_response}, print_output=False)
        self.assertFalse(result.passed)

        # Test with missing expiry date
        content = b"Contact: security@example.com\n"
        security_response = Response(None, content, None, 200, {"content-type": "text/plain"}, {}, None)
        result = check_security_txt_not_expired({"security_txt_response": security_response}, print_output=False)
        self.assertFalse(result.passed)
