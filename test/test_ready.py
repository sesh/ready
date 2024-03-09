from unittest import TestCase, skip

from ready.ready import ready


class ReadyTestCase(TestCase):
    def test_brntn(self):
        results = ready("brntn.me")
        failures = [r.check for r in results if not r.passed]
        self.assertEqual(failures, ["ssl_dns_caa_accounturi", "ssl_dns_caa_validationmethods"])

    def test_basehtml(self):
        results = ready("basehtml.xyz")
        failures = [r.check for r in results if not r.passed]
        self.assertEqual(
            failures,
            [
                "redirect_http",
                "ssl_hsts_preload",
                "csp_upgrade_insecure_requests",
                "csp_valid_directives",
                "report_to",
                "wellknown_robots",
                "wellknown_security",
                "wellknown_security_not_expired",
                "http_corp",
                "http_coop",
                "http_coep",
                "leaky_headers",
                "ssl_ocsp_must_staple",
                "ssl_dns_caa",
                "ssl_dns_caa_accounturi",
                "ssl_dns_caa_validationmethods",
                "email_dmarc_exists",
                "email_dmarc_none",
                "html_rel_icon",
                "html_unnecessary_entities",
                "html_x_dns_prefetch",
            ],
        )
