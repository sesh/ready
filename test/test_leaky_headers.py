from unittest import TestCase

from ready.checks.leaky_headers import check_should_not_include_leaky_headers
from ready.thttp import Response


class LeakyHeadersChecksTestCase(TestCase):
    def test_check_should_not_include_leaky_headers(self):
        r = Response(None, "", None, None, None, {}, None)
        result = check_should_not_include_leaky_headers({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, None, None, {"x-hosted-by": "22.11"}, None)
        result = check_should_not_include_leaky_headers({"response": r}, print_output=False)
        self.assertFalse(result.passed)
