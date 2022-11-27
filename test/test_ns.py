from ready.checks.ns import check_at_least_two_nameservers_configured
from unittest import TestCase
from thttp import Response

class NameserversTestCase(TestCase):

    def test_subdomain(self):
        # this should make an additional dns request
        responses = {
            "dns_ns_response": Response(None, None, {"Answer": []}, None, None, None, None),
            "dns_ns_response_fld": Response(None, None, {"Answer": ["ns1.example.com", "ns2.example.com", "ns3.example.com", "ns3.example.com"]})
        }
        result = check_at_least_two_nameservers_configured(responses, domain="subdomain.example.com", print_output=False)
        self.assertTrue(result.passed)
