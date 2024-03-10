from unittest import TestCase

from ready.checks.content import (
    check_http_response_should_include_content_type,
    check_http_response_should_be_gzipped,
    check_http_content_type_header_contains_charset,
    check_http_cache_control_is_included,
    check_http_p3p_header_is_not_set,
    check_http_expires_header_not_used_without_cache_control,
)
from ready.thttp import Response


class ContentChecksTestCase(TestCase):
    def test_check_http_response_should_include_content_type(self):
        r = Response(None, "", None, 200, None, {"content-type": "example/example"}, None)
        result = check_http_response_should_include_content_type({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_http_response_should_include_content_type({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_http_response_should_be_gzipped(self):
        r = Response(None, "", None, 200, None, {"content-encoding": "gzip; example"}, None)
        result = check_http_response_should_be_gzipped({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_http_response_should_be_gzipped({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_http_content_type_header_contains_charset(self):
        r = Response(None, "", None, 200, None, {"content-type": "example/example; charset=utf-8"}, None)
        result = check_http_content_type_header_contains_charset({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"content-type": "example/example"}, None)
        result = check_http_content_type_header_contains_charset({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_http_cache_control_is_included(self):
        r = Response(None, "", None, 200, None, {"cache-control": "nocache"}, None)
        result = check_http_cache_control_is_included({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_http_cache_control_is_included({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_http_p3p_header_is_not_set(self):
        r = Response(None, "", None, 200, None, {}, None)
        result = check_http_p3p_header_is_not_set({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"p3p": "some-value"}, None)
        result = check_http_p3p_header_is_not_set({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_http_expires_header_not_used_without_cache_control(self):
        r = Response(None, "", None, 200, None, {"cache-control": "maxage=20"}, None)
        result = check_http_expires_header_not_used_without_cache_control({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"cache-control": "maxage=20", "expires": "Wed, 21 Oct 2015 07:28:00 GMT"}, None)
        result = check_http_expires_header_not_used_without_cache_control({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"expires": "Wed, 21 Oct 2015 07:28:00 GMT"}, None)
        result = check_http_expires_header_not_used_without_cache_control({"response": r}, print_output=False)
        self.assertFalse(result.passed)
