"""
UNLICENSED
This is free and unencumbered software released into the public domain.

https://github.com/sesh/thttp
"""

import gzip
import json as json_lib
import ssl
from base64 import b64encode
from collections import namedtuple
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

Response = namedtuple("Response", "request content json status url headers cookiejar")


JSON_HEADERS = ["application/x-javascript", "application/json"]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(
    url,
    params={},
    json=None,
    data=None,
    headers={},
    method="GET",
    verify=True,
    redirect=True,
    cookiejar=None,
    basic_auth=None,
    timeout=None,
):
    """
    Returns a (named)tuple with the following properties:
        - request
        - content
        - json (dict; or None)
        - headers (dict; all lowercase keys)
            - https://stackoverflow.com/questions/5258977/are-http-headers-case-sensitive
        - status
        - url (final url, after any redirects)
        - cookiejar
    """
    method = method.upper()
    headers = {k.lower(): v for k, v in headers.items()}  # lowecase headers

    if params:
        url += "?" + urlencode(params)  # build URL from params
    if json and data:
        raise Exception("Cannot provide both json and data parameters")
    if method not in ["POST", "PATCH", "PUT"] and (json or data):
        raise Exception("Request method must POST, PATCH or PUT if json or data is provided")
    if not timeout:
        timeout = 60

    if json:  # if we have json, stringify and put it in our data variable
        headers["content-type"] = "application/json"
        data = json_lib.dumps(json).encode("utf-8")
    elif data:
        data = urlencode(data).encode()

    if basic_auth and len(basic_auth) == 2 and "authorization" not in headers:
        username, password = basic_auth
        headers["authorization"] = f'Basic {b64encode(f"{username}:{password}".encode()).decode("ascii")}'

    if not cookiejar:
        cookiejar = CookieJar()

    ctx = ssl.create_default_context()
    if not verify:  # ignore ssl errors
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    handlers = []
    handlers.append(HTTPSHandler(context=ctx))
    handlers.append(HTTPCookieProcessor(cookiejar=cookiejar))

    if not redirect:
        no_redirect = NoRedirect()
        handlers.append(no_redirect)

    opener = build_opener(*handlers)
    req = Request(url, data=data, headers=headers, method=method)

    try:
        with opener.open(req, timeout=timeout) as resp:
            status, content, resp_url = (resp.getcode(), resp.read(), resp.geturl())
            headers = {k.lower(): v for k, v in list(resp.info().items())}

            if "gzip" in headers.get("content-encoding", ""):
                content = gzip.decompress(content)

            json = json_lib.loads(content) if any([x in headers.get("content-type", "").lower() for x in JSON_HEADERS]) else None
    except HTTPError as e:
        status, content, resp_url = (e.code, e.read(), e.geturl())
        headers = {k.lower(): v for k, v in list(e.headers.items())}

        if "gzip" in headers.get("content-encoding", ""):
            content = gzip.decompress(content)

        json = json_lib.loads(content) if any([x in headers.get("content-type", "").lower() for x in JSON_HEADERS]) else None

    return Response(req, content, json, status, resp_url, headers, cookiejar)


import unittest


class RequestTestCase(unittest.TestCase):
    def test_cannot_provide_json_and_data(self):
        with self.assertRaises(Exception):
            request(
                "https://httpbingo.org/post",
                json={"name": "Brenton"},
                data="This is some form data",
            )

    def test_should_fail_if_json_or_data_and_not_p_method(self):
        with self.assertRaises(Exception):
            request("https://httpbingo.org/post", json={"name": "Brenton"})

        with self.assertRaises(Exception):
            request("https://httpbingo.org/post", json={"name": "Brenton"}, method="HEAD")

    def test_should_set_content_type_for_json_request(self):
        response = request("https://httpbingo.org/post", json={"name": "Brenton"}, method="POST")
        self.assertEqual(response.request.headers["Content-type"], "application/json")

    def test_should_work(self):
        response = request("https://httpbingo.org/get")
        self.assertEqual(response.status, 200)

    def test_should_create_url_from_params(self):
        response = request(
            "https://httpbingo.org/get",
            params={"name": "brenton", "library": "tiny-request"},
        )
        self.assertEqual(response.url, "https://httpbingo.org/get?name=brenton&library=tiny-request")

    def test_should_return_headers(self):
        response = request("https://httpbingo.org/response-headers", params={"Test-Header": "value"})
        self.assertEqual(response.headers["test-header"], "value")

    def test_should_populate_json(self):
        response = request("https://httpbingo.org/json")
        self.assertTrue("slideshow" in response.json)

    def test_should_return_response_for_404(self):
        response = request("https://httpbingo.org/404")
        self.assertEqual(response.status, 404)
        self.assertTrue("text/plain" in response.headers["content-type"])

    def test_should_fail_with_bad_ssl(self):
        with self.assertRaises(URLError):
            response = request("https://expired.badssl.com/")

    def test_should_load_bad_ssl_with_verify_false(self):
        response = request("https://expired.badssl.com/", verify=False)
        self.assertEqual(response.status, 200)

    def test_should_form_encode_non_json_post_requests(self):
        response = request("https://httpbingo.org/post", data={"name": "test-user"}, method="POST")
        self.assertEqual(response.json["form"]["name"], ["test-user"])

    def test_should_follow_redirect(self):
        response = request(
            "https://httpbingo.org/redirect-to",
            params={"url": "https://duckduckgo.com/"},
        )
        self.assertEqual(response.url, "https://duckduckgo.com/")
        self.assertEqual(response.status, 200)

    def test_should_not_follow_redirect_if_redirect_false(self):
        response = request(
            "https://httpbingo.org/redirect-to",
            params={"url": "https://duckduckgo.com/"},
            redirect=False,
        )
        self.assertEqual(response.status, 302)

    def test_cookies(self):
        response = request(
            "https://httpbingo.org/cookies/set",
            params={"cookie": "test"},
            redirect=False,
        )
        response = request("https://httpbingo.org/cookies", cookiejar=response.cookiejar)
        self.assertEqual(response.json["cookie"], "test")

    def test_basic_auth(self):
        response = request("http://httpbingo.org/basic-auth/user/passwd", basic_auth=("user", "passwd"))
        self.assertEqual(response.json["authorized"], True)

    def test_should_handle_gzip(self):
        response = request("http://httpbingo.org/gzip", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(response.json["gzipped"], True)

    def test_should_timeout(self):
        with self.assertRaises(TimeoutError):
            response = request("http://httpbingo.org/delay/3", timeout=1)


STATUS_CODES = {
    "100": "Continue",
    "101": "Switching Protocols",
    "102": "Processing",
    "103": "Early Hints",
    "200": "OK",
    "201": "Created",
    "202": "Accepted",
    "203": "Non-Authoritative Information",
    "204": "No Content",
    "205": "Reset Content",
    "206": "Partial Content",
    "207": "Multi-Status",
    "208": "Already Reported",
    "226": "IM Used",
    "300": "Multiple Choices",
    "301": "Moved Permanently",
    "302": "Found",
    "303": "See Other",
    "304": "Not Modified",
    "305": "Use Proxy",
    "307": "Temporary Redirect",
    "308": "Permanent Redirect",
    "400": "Bad Request",
    "401": "Unauthorized",
    "402": "Payment Required",
    "403": "Forbidden",
    "404": "Not Found",
    "405": "Method Not Allowed",
    "406": "Not Acceptable",
    "407": "Proxy Authentication Required",
    "408": "Request Timeout",
    "409": "Conflict",
    "410": "Gone",
    "411": "Length Required",
    "412": "Precondition Failed",
    "413": "Content Too Large",
    "414": "URI Too Long",
    "415": "Unsupported Media Type",
    "416": "Range Not Satisfiable",
    "417": "Expectation Failed",
    "418": "I'm a Teapot",
    "421": "Misdirected Request",
    "422": "Unprocessable Content",
    "423": "Locked",
    "424": "Failed Dependency",
    "425": "Too Early",
    "426": "Upgrade Required",
    "427": "Unassigned: ",
    "428": "Precondition Required",
    "429": "Too Many Requests",
    "431": "Request Header Fields Too Large",
    "451": "Unavailable For Legal Reasons",
    "500": "Internal Server Error",
    "501": "Not Implemented",
    "502": "Bad Gateway",
    "503": "Service Unavailable",
    "504": "Gateway Timeout",
    "505": "HTTP Version Not Supported",
    "506": "Variant Also Negotiates",
    "507": "Insufficient Storage",
    "508": "Loop Detected",
    "509": "Unassigned: ",
    "510": "Not Extended",
    "511": "Network Authentication Required",
}


def pretty(response, content=False):
    RESET = "\033[0m"
    HIGHLIGHT = "\033[34m"

    # status code
    print(HIGHLIGHT + str(response.status) + " " + RESET + STATUS_CODES[str(response.status)])

    # headers
    for k in sorted(response.headers.keys()):
        print(HIGHLIGHT + k + RESET + ": " + response.headers[k])

    if content:
        # blank line
        print()

        # response body
        if response.json:
            print(json_lib.dumps(response.json, indent=2))
        else:
            print(response.content.decode())
