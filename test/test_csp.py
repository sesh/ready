from unittest import TestCase

from ready.checks.csp import extract_csp
from ready.thttp import Response


class ReadyTestCase(TestCase):
    def test_extract_csp_meta_tag(self):
        content = """<!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="description" content="">
            <meta
              http-equiv="Content-Security-Policy"
              content="default-src 'self'; img-src https://*; child-src 'none';" />

            <title>Minimal base.html</title>
        </head>
        <body>

            <!-- Delete this part -->
            <h1>base.html</h1>
            <p>The absolute minimum <code>base.html</code> to get your project started.</p>
            <h3>Usage:</h3>
            <pre>
              curl https://basehtml.xyz &gt; base.html
            </pre>
            <a href="https://github.com/sesh/base.html">more info</a>
        </body>
        </html>"""

        # request content json status url headers cookiejar
        response = Response(None, content, None, None, None, {}, None)

        try:
            from bs4 import BeautifulSoup

            csp = extract_csp(response)
            self.assertEqual(csp, "default-src 'self'; img-src https://*; child-src 'none';")
        except ImportError:
            print("Not executing CSP test because beautifulsoup is not available.")
