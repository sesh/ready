from unittest import TestCase

from ready.checks.report_to import check_report_to_header_must_not_be_included_in_response
from ready.thttp import Response


class ReportToChecksTestCase(TestCase):
    def test_check_report_to_header_must_not_be_included_in_response(self):
        r = Response(None, "", None, None, None, {}, None)
        result = check_report_to_header_must_not_be_included_in_response({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, None, None, {"report-to": "some-value"}, None)
        result = check_report_to_header_must_not_be_included_in_response({"response": r}, print_output=False)
        self.assertFalse(result.passed)
