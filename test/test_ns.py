from unittest import TestCase

from ready.checks.ns import check_at_least_two_nameservers_configured
from ready.thttp import Response


class NameserversTestCase(TestCase):
    def test_subdomain(self):
        # this should make an additional dns request
        responses = {
            "dns_ns_response": Response(None, None, {"Answer": []}, None, None, None, None),
            "dns_ns_response_fld": Response(
                None,
                None,
                {
                    "Answer": [
                        {"data": "ns1.example.com"},
                        {"data": "ns2.example.com"},
                        {"data": "ns3.example.com"},
                        {"data": "ns3.example.com"},
                    ]
                },
                None,
                None,
                None,
                None,
            ),
        }
        result = check_at_least_two_nameservers_configured(responses, domain="subdomain.example.com", print_output=False)
        self.assertTrue(result.passed)
