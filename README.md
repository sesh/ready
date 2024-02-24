`ready` is a tool for developers to check how production ready their website.


## Usage

Install the tool from PyPI with:

```
pip install ready-check
```

Running the checks for a domain is as simple as:

```
ready <domain>
```

For more options, check the output of `--help`.

### Usage during development

If you have cloned the repository and would like to run the checks with your local version, simply run:

```
python3 -m ready.ready <domain> [--request-filter=<x>] [--check-filter=<x>]
```


### Optional Dependencies

There are no required dependencies, but two optional dependencies that enable some additional behaviour:

- Installing the `tld` package adds support for using the fully-qualified domain name for some DNS-related checks. This is particularly handy if you need to check a subdomain.
- Installing `beautifulsoup4` adds support for extracting the Content-Security-Policy from the HTML document as well as the headers. This technique can be used for sites that use static hosting like Github Pages.

Note: if you install from PyPI these dependencies are installed.


## Check list

- Cookies should set the SameSite flag
- Cookies should set the Secure flag
- Cookies should set the HttpOnly flag
- Swagger URLs should not return 200 (requires --fuzz)
- HSTS Header should be included in response
- HSTS Header should have a long max-age
- HSTS Header should have includeSubdomains
- HSTS Header should have preload
- An AAAA DNS record exists (IPv6 Support)
- HTTP -> HTTPS redirection occurs
- Permissions-Policy should exist if the response is HTML
- frame-ancestors should be in CSP or X-Frame-Options should exist if the response is HTML
- X-Content-Type-options should be "nosniff"
- Referrer-Policy should be set
- X-XSS-Protection header should not exist
- HTML should start with "<!doctype html>"
- `<html>` tag should include lang
- HTML should include meta charset tag
- HTML should include `<title>`
- HTML should include link with rel="icon"
- HTML should not use schemeless urls for links or hrefs
- HTML should not use unnecessary HTML entities
- All script tags should use subresource integrity
- X-DNS-Prefetch-Control should be set to off
- CDNs should not be used for Javascript or CSS assets
- RSS and JSON feeds should return Access-Control-Allow-Origin header
- Cache-Control max-age should be <= 86400 for HTML documents
- Content-Security-Policy header should exist
- Content-Security-Policy header should start with default-src 'none'
- Content-Security-Policy must include either default-src or script-src
- Content-Security-Policy header must not include unsafe-inline
- Content-Security-Policy header must not include unsafe-eval
- Content-Security-Policy header must not include report-sample
- Content-Security-Policy header must not include report-uri
- Content-Security-Policy header should not include report-to
- Content-Security-Policy header should include upgrade-insecure-requests
- Content-Security-Policy header only includes valid directives
- At least two nameservers should be configured
- Cross-Origin-Resource-Policy should be "same-origin"
- cross-origin-opener-policy should be "same-origin"
- Cross-Origin-Embedder-Policy should be "require-corp"
- Report-To Header must not be included in response
- Response should not contain hints of a Cloudflare captcha page
- Response should not contain hints of a Kasada error page
- Response should include a Content-Type
- Response should be gzipped
- Content-Type header should contain charset
- Expires header is deprecated and should not be returned
- Cache-Control header should be included in the response
- P3P header is deprecated and should not be returned
- SPF TXT record should exist
- SPF TXT record should contain "-all"
- SPF DNS record is depreciated and should not exist
- SPF includes use less than 10 DNS requests
- DMARC record should exist
- DMARC record should contain p=reject
- SPF should be "v=spf1 -all" if there are no MX records or MX record is "."
- Robots.txt exists and is a text file
- Security.txt exists and is a text file that contains required attributes
- Security.txt has an expiry date in the future
- Favicon is served at /favicon.ico
- Headers that leak information should not be in the response
- SSL certificate should be trusted
- SSL expiry should be less than one year
- SSL expiry should be greater than five days
- SSL connection fails when using TLS 1.1
- SSL connection fails when using TLS 1.0
- DNS CAA should be enabled
- DNS CAA should include accounturi
- DNS CAA should include validationmethods
- Response should be a 200 (after redirects)


### Potential / WIP

- GraphQL introspection is not enabled
- DNSSEC is supported
- DKIM is configured
- SPF must not contain +all or ?all
- DMARC / SPF configuration when there is no MX record
- CSP should contain default-src or script-src (there's no XSS protection by default)
- Detections for different WAFs that might be returning instead of the intended content (Cloudflare, Imperva, Kasada, etc.)
- DNS TTL should be > 300, this reduces the number of DNS requests clients need to make
- CSP: default-src or script-src must be set
- CSP: object-src none must be set
- Check for source maps in JS
- HTML: contains viewport


## Not in scope

Some things are best left to other tools, or are generally handled in other ways by web development teams.

- Dependency scanning. Use a service to regularly check that you are using the latest version of your dependencies.
- Vulnerability scanning. This tool doesn't replace a penetration test, or automated penetration testing tools.
- Scans for specific CMSs (i.e. Wordpress, Drupal, etc.). You know what CMS you are using, and you should run framework/cms specific tools in addition to this.
- Checking for dead links. Use [`muffet`](https://github.com/raviqqe/muffet) or similar for that one.
- Scans for specific WAFs (use wafw00f for detection)


## Standard Checks

This tool overlaps with a bunch of other online site checking tools.
Here's a few that I have used in the past:

- https://webhint.io/
- https://pagespeed.web.dev/
- https://internet.nl/
- https://www.ssllabs.com/ssltest/
- https://securityheaders.com/
- https://csp-evaluator.withgoogle.com/
- https://observatory.mozilla.org/
- https://tools.pingdom.com/
