from ready.checks.swagger import check_swagger_should_not_return_200, SWAGGER_PATHS
from unittest import TestCase


from ready.thttp import Response
from unittest.mock import patch


class SwaggerChecksTestCase(TestCase):
    def test_check_swagger_should_not_return_200(self):
        mocked_response = Response(None, "", None, 404, None, None, None)
        r = Response(None, "", None, 200, "https://ready.invalid", {}, None)

        with patch("ready.checks.swagger.request", return_value=mocked_response):
            result = check_swagger_should_not_return_200({"response": r}, print_output=False)
            self.assertTrue(result.passed)

        mocked_response = Response(None, "", None, 200, None, None, None)
        with patch("ready.checks.swagger.request", return_value=mocked_response):
            result = check_swagger_should_not_return_200({"response": r}, print_output=False)
            self.assertFalse(result.passed)
