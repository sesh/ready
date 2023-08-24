import re
from urllib.parse import urljoin

from ready.result import result
from ready.thttp import request

SWAGGER_PATHS = [
    "core/latest/swagger-ui/index.html",
    "csp/gateway/slc/api/swagger-ui.html",
    "swagger",
    "swagger-resources",
    "swagger-ui",
    "swagger-ui.html",
    "swagger.json",
    "swagger.yaml",
    "swagger/index.html",
    "swagger/swagger-ui.htm",
    "swagger/swagger-ui.html",
    "swagger/ui",
    "swagger/v1/swagger.json",
    "swaggerui",
]


# Check: Swagger URLs should not return 200 (requires --fuzz)
def check_swagger_should_not_return_200(responses, **kwargs):
    url = responses["response"].url

    swagger_responses = []
    for path in SWAGGER_PATHS:
        response = request(urljoin(url, path))
        if response.status < 299:
            swagger_responses.append(response)

    return result(
        len(swagger_responses) == 0,
        f"Swagger URLs should not return 200 ({[(r.url, r.status) for r in swagger_responses]})",
        "cors_header_exists",
        **kwargs,
    )
