from unittest import TestCase

from ready.checks.status import check_http_response_should_be_200
from ready.thttp import Response


class StatusChecksTestCase(TestCase):
    def test_check_http_response_should_be_200(self):
        r = Response(None, "", None, 200, None, {}, None)
        result = check_http_response_should_be_200({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 499, None, {}, None)
        result = check_http_response_should_be_200({"response": r}, print_output=False)
        self.assertFalse(result.passed)
