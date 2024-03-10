from unittest import TestCase, skipIf

from ready.checks.csp import (
    extract_csp,
    check_csp_should_exist,
    check_csp_should_start_with_defaultsrc_none,
    check_csp_includes_default_or_script_directive,
    check_csp_must_not_include_unsafe_eval,
    check_csp_must_not_include_unsafe_inline,
    check_csp_must_not_include_report_sample,
    check_csp_must_not_include_reporturi,
    check_csp_should_not_include_reportto,
    check_csp_upgrade_insecure_requests,
    check_csp_should_only_include_valid_directives,
)
from ready.thttp import Response

SKIP_BS4_TESTS = False
try:
    import bs4
except ImportError:
    SKIP_BS4_TESTS = True


response_with_html_csp = Response(
    None,
    """<!doctype html>
        <meta
          http-equiv="Content-Security-Policy"
          content="default-src 'self'; img-src https://*; child-src 'none';" />
    </head>""",
    None,
    None,
    None,
    {},
    None,
)


def response_with_csp(csp):
    return Response(None, "", None, None, None, {"content-security-policy": csp}, None)


class ExtractContentSecurityPolicyTestCase(TestCase):
    @skipIf(SKIP_BS4_TESTS, "beautifulsoup is not available")
    def test_extract_csp_meta_tag(self):
        from bs4 import BeautifulSoup

        csp = extract_csp(response_with_html_csp)
        self.assertEqual(csp, "default-src 'self'; img-src https://*; child-src 'none';")

    def test_extract_csp_from_header(self):
        csp = extract_csp(response_with_csp("default-src 'none';"))
        self.assertEqual(csp, "default-src 'none';")

    def test_extract_csp_empry(self):
        csp = extract_csp(Response(None, "", None, None, None, {}, None))
        self.assertEqual(csp, None)


class ContentSecurityPolicyChecksTestCase(TestCase):
    def test_check_csp_should_exist(self):
        result = check_csp_should_exist({"response": response_with_csp("default-src 'none';")}, print_output=False)
        self.assertTrue(result.passed)

        result = check_csp_should_exist({"response": Response(None, "", None, None, None, {}, None)}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_csp_should_start_with_defaultsrc_none(self):
        result = check_csp_should_start_with_defaultsrc_none(
            {"response": response_with_csp("default-src 'none';")}, print_output=False
        )
        self.assertTrue(result.passed)

        result = check_csp_should_start_with_defaultsrc_none(
            {"response": response_with_csp("default-src 'self';")}, print_output=False
        )
        self.assertFalse(result.passed)

    def test_check_csp_includes_default_or_script_directive(self):
        result = check_csp_includes_default_or_script_directive(
            {"response": response_with_csp("default-src 'none';")}, print_output=False
        )
        self.assertTrue(result.passed)

        result = check_csp_includes_default_or_script_directive(
            {"response": response_with_csp("script-src 'none';")}, print_output=False
        )
        self.assertTrue(result.passed)

        result = check_csp_includes_default_or_script_directive(
            {"response": response_with_csp("default-src 'none'; script-src 'self'")}, print_output=False
        )
        self.assertTrue(result.passed)

        result = check_csp_includes_default_or_script_directive(
            {"response": response_with_csp("upgrade-insecure-requests")}, print_output=False
        )
        self.assertFalse(result.passed)

    def test_check_csp_must_not_include_unsafe_eval(self):
        result = check_csp_must_not_include_unsafe_eval(
            {"response": response_with_csp("default-src 'none';")}, print_output=False
        )
        self.assertTrue(result.passed)

        result = check_csp_must_not_include_unsafe_eval(
            {"response": response_with_csp("default-src 'none'; unsafe-eval;")}, print_output=False
        )
        self.assertFalse(result.passed)

        result = check_csp_must_not_include_unsafe_eval(
            {"response": response_with_csp("default-src 'none'; UnSafe-EVAL")}, print_output=False
        )
        self.assertFalse(result.passed)

    def test_check_csp_must_not_include_unsafe_inline(self):
        result = check_csp_must_not_include_unsafe_inline(
            {"response": response_with_csp("default-src 'none';")}, print_output=False
        )
        self.assertTrue(result.passed)

        result = check_csp_must_not_include_unsafe_inline(
            {"response": response_with_csp("default-src 'none'; unsafe-inline;")}, print_output=False
        )
        self.assertFalse(result.passed)

        result = check_csp_must_not_include_unsafe_inline(
            {"response": response_with_csp("default-src 'none'; UnSafe-inLINe")}, print_output=False
        )
        self.assertFalse(result.passed)

    def test_check_csp_must_not_include_report_sample(self):
        result = check_csp_must_not_include_report_sample(
            {"response": response_with_csp("default-src 'none';")}, print_output=False
        )
        self.assertTrue(result.passed)

        result = check_csp_must_not_include_report_sample(
            {"response": response_with_csp("default-src 'none'; unsafe-inline; script-sample")}, print_output=False
        )
        self.assertFalse(result.passed)

    def test_check_csp_must_not_include_reporturi(self):
        result = check_csp_must_not_include_reporturi({"response": response_with_csp("default-src 'none';")}, print_output=False)
        self.assertTrue(result.passed)

        result = check_csp_must_not_include_reporturi(
            {"response": response_with_csp("default-src 'none'; report-uri https://example.org")}, print_output=False
        )
        self.assertFalse(result.passed)

    def test_check_csp_should_not_include_reportto(self):
        result = check_csp_should_not_include_reportto(
            {"response": response_with_csp("default-src 'none';")}, print_output=False
        )
        self.assertTrue(result.passed)

        result = check_csp_should_not_include_reportto(
            {"response": response_with_csp("default-src 'none'; report-to example")}, print_output=False
        )
        self.assertFalse(result.passed)

    def test_check_csp_upgrade_insecure_requests(self):
        result = check_csp_upgrade_insecure_requests(
            {"response": response_with_csp("default-src 'none'; upgrade-insecure-requests")}, print_output=False
        )
        self.assertTrue(result.passed)

        result = check_csp_upgrade_insecure_requests({"response": response_with_csp("default-src 'none'")}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_csp_should_only_include_valid_directives(self):
        result = check_csp_should_only_include_valid_directives(
            {"response": response_with_csp("default-src 'none'; upgrade-insecure-requests; invalid-directive;")},
            print_output=False,
        )
        self.assertFalse(result.passed)

    def test_checks_fail_with_missing_csp(self):
        checks = [
            check_csp_should_exist,
            check_csp_should_start_with_defaultsrc_none,
            check_csp_includes_default_or_script_directive,
            check_csp_upgrade_insecure_requests,
        ]

        for c in checks:
            result = c({"response": Response(None, "", None, None, None, {}, None)}, print_output=False)
            self.assertFalse(result.passed)

            result = c({"response": response_with_csp("")}, print_output=False)
            self.assertFalse(result.passed)

    def test_long_csp_should_be_truncated(self):
        result = check_csp_should_exist(
            {
                "response": response_with_csp(
                    "default-src 'none'; base-uri 'self'; child-src ready.invalid/assets-cdn/worker/ gist.ready.invalid/assets-cdn/worker/; connect-src 'self' uploads.ready.invalid collector.ready.invalid raw.ready.invalid api.ready.invalid  objects-origin.ready.invalid *.actions.ready.invalid wss://*.actions.ready.invalid insights.ready.invalid wss://alive.ready.invalid github.ready.invalid; font-src github.ready.invalid; form-action 'self' ready.invalid gist.ready.invalid objects-origin.ready.invalid; frame-ancestors 'none'; frame-src viewscreen.ready.invalid notebooks.ready.invalid; img-src 'self' data: github.ready.invalid media.ready.invalid camo.ready.invalid identicons.ready.invalid avatars.ready.invalid objects.ready.invalid secured-user-images.ready.invalid/ user-images.ready.invalid/ private-user-images.ready.invalid opengraph.ready.invalid customer-stories-feed.ready.invalid spotlights-feed.ready.invalid objects-origin.ready.invalid *.ready.invalid; manifest-src 'self'; media-src ready.invalid user-images.ready.invalid/ secured-user-images.ready.invalid/ private-user-images.ready.invalid github-production-user-asset-6210df.s3.amazonaws.com gist.ready.invalid github.ready.invalid; script-src github.ready.invalid; style-src 'unsafe-inline' github.ready.invalid; upgrade-insecure-requests; worker-src ready.invalid/assets-cdn/worker/ gist.ready.invalid/assets-cdn/worker/"
                )
            },
            print_output=False,
        )
        self.assertTrue("uploads.ready.invalid" in result.message)
        self.assertFalse("worker-src ready.invalid" in result.message)
