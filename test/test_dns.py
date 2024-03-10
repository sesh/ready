from unittest import TestCase

from ready.checks.dns import check_aaaa_record_exists
from ready.thttp import Response


class DnsChecksTestCase(TestCase):
    def test_check_aaaa_record_exists(self):
        r = Response(None, "", {"Answer": [{"data": ""}]}, 200, None, {}, None)

        result = check_aaaa_record_exists({"dns_aaaa_response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", {"Answer": []}, 200, None, {}, None)

        result = check_aaaa_record_exists({"dns_aaaa_response": r}, print_output=False)
        self.assertFalse(result.passed)
