import re

from ready.result import result

LEAKY_HEADERS = [
    "apigw-requestid",
    "cdn-cache",
    "cf-edge-cache",
    "fastly-debug-states",
    "fly-request-id",
    "ghost-fastly",
    "served-by",
    "server",
    "x-appversion",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-backend-name",
    "x-backend-server",
    "x-backend",
    "x-build-id",
    "x-build",
    "x-cache-info",
    "x-cache-key",
    "x-cache-rule",
    "x-cached-by",
    "x-cdn-rule",
    "x-cdn",
    "x-cf-worker",
    "x-client-ip",
    "x-diaspora-version",
    "x-drupal-theme",
    "x-fastly-request-id",
    "x-fw-version",
    "x-generator",
    "x-github-backend",
    "x-hosted-by",
    "x-httpd",
    "x-kinja-revision",
    "x-lambda-id",
    "x-last-commmit-hash",
    "x-litespeed-cache",
    "x-nextjs-page",
    "x-nodejs",
    "x-origin-server",
    "x-powered-by-plesk",
    "x-powered-by",
    "x-powered",
    "x-protected-by",
    "x-provided-by",
    "x-section",
    "x-server-powered-by",
    "x-server",
    "x-tumblr-user",
    "x-varnish",
    "x-vercel-id",
    "x-version",
    "via",
]


# Check: Headers that leak information should not be in the response
def check_should_not_include_leaky_headers(responses, **kwargs):
    leaky = [x for x in LEAKY_HEADERS if re.search(r"\d\.\d", responses["response"].headers.get(x, "")) != None]
    return result(
        len(leaky) == 0,
        f"Headers that leak information should not be in the response ({leaky})",
        "leaky_headers",
        **kwargs,
    )
