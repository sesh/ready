from unittest import TestCase

from ready.checks.redirect import check_http_to_https_redirect
from ready.thttp import Response


class RedirectChecksTestCase(TestCase):
    def test_check_http_to_https_redirect(self):
        r = Response(None, "", None, 200, "https://ready.invalid", {}, None)
        result = check_http_to_https_redirect({"http_response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, "http://ready.invalid", {}, None)
        result = check_http_to_https_redirect({"http_response": r}, print_output=False)
        self.assertFalse(result.passed)

        result = check_http_to_https_redirect({"http_response": None}, print_output=False)
        self.assertFalse(result.passed)
