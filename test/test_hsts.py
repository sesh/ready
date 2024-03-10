from unittest import TestCase

from ready.checks.hsts import (
    check_hsts_header_should_be_included_in_response,
    check_hsts_header_should_have_a_long_max_age,
    check_hsts_header_should_have_includesubdomains,
    check_hsts_header_should_have_preload,
)
from ready.thttp import Response


class HstsChecksTestCase(TestCase):
    def test_check_hsts_header_should_be_included_in_response(self):
        r = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=0"}, None)
        result = check_hsts_header_should_be_included_in_response({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_hsts_header_should_be_included_in_response({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_hsts_header_should_have_a_long_max_age(self):
        r = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=31536001"}, None)
        result = check_hsts_header_should_have_a_long_max_age({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=0"}, None)
        result = check_hsts_header_should_have_a_long_max_age({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_hsts_header_should_have_includesubdomains(self):
        r = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=0; includeSubDomains"}, None)
        result = check_hsts_header_should_have_includesubdomains({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=0;"}, None)
        r_fld = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=0; includeSubDomains"}, None)
        result = check_hsts_header_should_have_includesubdomains({"response": r, "response_fld": r_fld}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        r_fld = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=0; includeSubDomains"}, None)
        result = check_hsts_header_should_have_includesubdomains({"response": r, "response_fld": r_fld}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_hsts_header_should_have_includesubdomains({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_hsts_header_should_have_preload(self):
        r = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=0; preload; includeSubDomains"}, None)
        result = check_hsts_header_should_have_preload({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=0;"}, None)
        r_fld = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=0; preload; includeSubDomains"}, None)
        result = check_hsts_header_should_have_preload({"response": r, "response_fld": r_fld}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        r_fld = Response(None, "", None, 200, None, {"strict-transport-security": "max-age=0; preload; includeSubDomains"}, None)
        result = check_hsts_header_should_have_preload({"response": r, "response_fld": r_fld}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_hsts_header_should_have_preload({"response": r}, print_output=False)
        self.assertFalse(result.passed)
