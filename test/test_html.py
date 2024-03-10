from unittest import TestCase
from unittest.mock import patch
from ready.checks.html import (
    check_permissions_policy_should_exist,
    check_frame_ancestors_should_exist,
    check_x_content_type_options_should_be_nosniff,
    check_referrer_policy_should_be_set,
    check_x_xss_protection_should_not_exist,
    check_html_starts_with_doctype,
    check_html_tag_includes_lang,
    check_html_meta_charset,
    check_html_includes_title,
    check_html_includes_rel_icon,
    check_html_should_not_use_schemeless_urls,
    check_html_should_not_use_unnecessary_entities,
    check_html_script_tags_use_sri,
    check_x_dns_prefetch_control_is_off,
    check_cdns_should_not_be_used,
    check_rss_should_return_cors_header,
    check_html_should_not_be_cached_for_more_than_24_hours,
)

from ready.thttp import Response


class HtmlChecksTestCase(TestCase):
    def test_check_permissions_policy_should_exist(self):
        r = Response(None, "", None, 200, None, {"permissions-policy": "camera=()"}, None)
        result = check_permissions_policy_should_exist({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_permissions_policy_should_exist({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_frame_ancestors_should_exist(self):
        r = Response(None, "", None, 200, None, {"x-frame-options": "DENY"}, None)
        result = check_frame_ancestors_should_exist({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"content-security-policy": "frame-ancestors 'none'"}, None)
        result = check_frame_ancestors_should_exist({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_frame_ancestors_should_exist({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_x_content_type_options_should_be_nosniff(self):
        r = Response(None, "", None, 200, None, {"x-content-type-options": "nosniff"}, None)
        result = check_x_content_type_options_should_be_nosniff({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"x-content-type-options": "other-value"}, None)
        result = check_x_content_type_options_should_be_nosniff({"response": r}, print_output=False)
        self.assertFalse(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_x_content_type_options_should_be_nosniff({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_referrer_policy_should_be_set(self):
        r = Response(None, "", None, 200, None, {"referrer-policy": "no-referrer"}, None)
        result = check_referrer_policy_should_be_set({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_referrer_policy_should_be_set({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_x_xss_protection_should_not_exist(self):
        r = Response(None, "", None, 200, None, {}, None)
        result = check_x_xss_protection_should_not_exist({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {"x-xss-protection": "some-value"}, None)
        result = check_x_xss_protection_should_not_exist({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_html_starts_with_doctype(self):
        r = Response(None, b"    <!doctype html><meta description='test' />", None, 200, None, {}, None)
        result = check_html_starts_with_doctype({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"aaaa<!doctype html><meta description='test' />", None, 200, None, {}, None)
        result = check_html_starts_with_doctype({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_html_tag_includes_lang(self):
        r = Response(None, b"<html js lang='en'>", None, 200, None, {}, None)
        result = check_html_tag_includes_lang({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"<html js>", None, 200, None, {}, None)
        result = check_html_tag_includes_lang({"response": r}, print_output=False)
        self.assertFalse(result.passed)

        r = Response(None, b"", None, 200, None, {}, None)
        result = check_html_tag_includes_lang({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_html_meta_charset(self):
        r = Response(None, b"<html js lang='en'><meta charset='utf-8'>", None, 200, None, {}, None)
        result = check_html_meta_charset({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"", None, 200, None, {}, None)
        result = check_html_meta_charset({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_html_includes_title(self):
        r = Response(None, b"<html js lang='en'><title>Test</title>", None, 200, None, {}, None)
        result = check_html_includes_title({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"", None, 200, None, {}, None)
        result = check_html_includes_title({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_html_includes_rel_icon(self):
        r = Response(None, b"<link rel='icon' href='favicon.ico'>", None, 200, None, {}, None)
        result = check_html_includes_rel_icon({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"<link href='favicon.ico' rel='icon'>", None, 200, None, {}, None)
        result = check_html_includes_rel_icon({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"<link rel='shortcut icon' href='favicon.ico'>", None, 200, None, {}, None)
        result = check_html_includes_rel_icon({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"<link href='favicon.ico' rel='shortcut icon'>", None, 200, None, {}, None)
        result = check_html_includes_rel_icon({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"", None, 200, None, {}, None)
        result = check_html_includes_rel_icon({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_html_should_not_use_schemeless_urls(self):
        r = Response(None, b"<html>", None, 200, None, {}, None)
        result = check_html_should_not_use_schemeless_urls({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"='//'", None, 200, None, {}, None)
        result = check_html_should_not_use_schemeless_urls({"response": r}, print_output=False)
        self.assertFalse(result.passed)

        r = Response(None, b'="//"', None, 200, None, {}, None)
        result = check_html_should_not_use_schemeless_urls({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_html_should_not_use_unnecessary_entities(self):
        r = Response(None, b"<html>", None, 200, None, {}, None)
        result = check_html_should_not_use_unnecessary_entities({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"&nbsp;", None, 200, None, {}, None)
        result = check_html_should_not_use_unnecessary_entities({"response": r}, print_output=False)
        self.assertFalse(result.passed)

        r = Response(None, b"&nbsp;&amp;&quot;", None, 200, None, {}, None)
        result = check_html_should_not_use_unnecessary_entities({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_html_script_tags_use_sri(self):
        r = Response(None, b'<script src="example.js" integrity="sha256-abc123"></script>', None, 200, None, {}, None)
        result = check_html_script_tags_use_sri({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b'<script src="example.js"></script>', None, 200, None, {}, None)
        result = check_html_script_tags_use_sri({"response": r}, print_output=False)
        self.assertFalse(result.passed)

        r = Response(
            None,
            b'<script src="example1.js"></script><script src="example2.js" integrity="sha256-abc123"></script>',
            None,
            200,
            None,
            {},
            None,
        )
        result = check_html_script_tags_use_sri({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_x_dns_prefetch_control_is_off(self):
        r = Response(None, b"", None, 200, None, {"x-dns-prefetch-control": "off"}, None)
        result = check_x_dns_prefetch_control_is_off({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"", None, 200, None, {"x-dns-prefetch-control": "on"}, None)
        result = check_x_dns_prefetch_control_is_off({"response": r}, print_output=False)
        self.assertFalse(result.passed)

        r = Response(None, b"", None, 200, None, {}, None)
        result = check_x_dns_prefetch_control_is_off({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_cdns_should_not_be_used(self):
        r = Response(
            None, b'<script src="local.js"></script><link rel="stylesheet" href="local.css">', None, 200, None, {}, None
        )
        result = check_cdns_should_not_be_used({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b'<script src="https://cdn.jsdelivr.net/example.js"></script>', None, 200, None, {}, None)
        result = check_cdns_should_not_be_used({"response": r}, print_output=False)
        self.assertFalse(result.passed)

        r = Response(None, b'<link rel="stylesheet" href="https://cdnjs.cloudflare.com/example.css">', None, 200, None, {}, None)
        result = check_cdns_should_not_be_used({"response": r}, print_output=False)
        self.assertFalse(result.passed)

        r = Response(
            None,
            b'<script src="local.js"></script><link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">',
            None,
            200,
            None,
            {},
            None,
        )
        result = check_cdns_should_not_be_used({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_html_should_not_be_cached_for_more_than_24_hours(self):
        r = Response(None, b"", None, 200, None, {"cache-control": "max-age=86400"}, None)
        result = check_html_should_not_be_cached_for_more_than_24_hours({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, b"", None, 200, None, {"cache-control": "max-age=90000"}, None)
        result = check_html_should_not_be_cached_for_more_than_24_hours({"response": r}, print_output=False)
        self.assertFalse(result.passed)

        r = Response(None, b"", None, 200, None, {}, None)
        result = check_html_should_not_be_cached_for_more_than_24_hours({"response": r}, print_output=False)
        self.assertFalse(result.passed)

        r = Response(None, b"", None, 200, None, {"cache-control": "max-age=abc"}, None)
        result = check_html_should_not_be_cached_for_more_than_24_hours({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_rss_should_return_cors_header(self):
        mock_response = Response(None, b"", None, 200, None, {"access-control-allow-origin": "*"}, None)
        with patch("ready.checks.html.thttp.request", return_value=mock_response):
            r = Response(
                None,
                b'<link rel="alternate" type="application/rss+xml" href="https://thttp.invalid/feed.rss">',
                None,
                200,
                "https://ready.invalid",
                {},
                None,
            )
            result = check_rss_should_return_cors_header({"response": r}, print_output=False)
            self.assertTrue(result.passed)

            r = Response(
                None,
                b'<link rel="alternate" type="application/rss+xml" href="//thttp.invalid/feed.rss">',
                None,
                200,
                "https://ready.invalid",
                {},
                None,
            )
            result = check_rss_should_return_cors_header({"response": r}, print_output=False)
            self.assertTrue(result.passed)

            r = Response(
                None,
                b'<link rel="alternate" type="application/rss+xml" href="/feed.rss">',
                None,
                200,
                "https://ready.invalid",
                {},
                None,
            )
            result = check_rss_should_return_cors_header({"response": r}, print_output=False)
            self.assertTrue(result.passed)

        mock_response = Response(None, b"", None, 200, None, {}, None)
        with patch("ready.checks.html.thttp.request", return_value=mock_response):
            r = Response(
                None,
                b'<link rel="alternate" type="application/rss+xml" href="https://thttp.invalid/feed.rss">',
                None,
                200,
                {},
                {},
                None,
            )
            result = check_rss_should_return_cors_header({"response": r}, print_output=False)
            self.assertFalse(result.passed)
