from unittest import TestCase

from ready.checks.corp_coop_coep import (
    check_cross_origin_resource_policy_should_be_sameorigin,
    check_cross_origin_opener_policy_should_be_sameorigin,
    check_cross_origin_embedder_policy_should_be_require_corp,
)
from ready.thttp import Response


class CorpCoopCoepChecksTestCase(TestCase):
    def test_check_cross_origin_resource_policy_should_be_sameorigin(self):
        r = Response(
            None,
            "",
            None,
            200,
            None,
            {
                "cross-origin-resource-policy": "same-origin",
            },
            None,
        )
        result = check_cross_origin_resource_policy_should_be_sameorigin({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_cross_origin_resource_policy_should_be_sameorigin({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_cross_origin_opener_policy_should_be_sameorigin(self):
        r = Response(
            None,
            "",
            None,
            200,
            None,
            {
                "cross-origin-opener-policy": "same-origin",
            },
            None,
        )
        result = check_cross_origin_opener_policy_should_be_sameorigin({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_cross_origin_opener_policy_should_be_sameorigin({"response": r}, print_output=False)
        self.assertFalse(result.passed)

    def test_check_cross_origin_embedder_policy_should_be_require_corp(self):
        r = Response(
            None,
            "",
            None,
            200,
            None,
            {
                "cross-origin-embedder-policy": "require-corp",
            },
            None,
        )
        result = check_cross_origin_embedder_policy_should_be_require_corp({"response": r}, print_output=False)
        self.assertTrue(result.passed)

        r = Response(None, "", None, 200, None, {}, None)
        result = check_cross_origin_embedder_policy_should_be_require_corp({"response": r}, print_output=False)
        self.assertFalse(result.passed)
