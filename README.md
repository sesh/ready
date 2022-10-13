`ready` is a tool for developers to check how production ready their website or API is.


## Usage

```
python3 -m ready.ready <domain>
```


## Checklist

- Cookies should set the SameSite flag
- Cookies should set the Secure flag
- Cookies should set the HttpOnly flag
- Swagger URLs should not return 200 (requires --fuzz)
- HSTS Header should be included in response
- HSTS Header should have a long max-age
- HSTS Header should have includeSubdomains
- HSTS Header should have preload
- An AAAA DNS record exists (IPv6 Support)
- Access-Control-Allow-Origin header is in the response
- Access-Control-Allow-Origin is not set to "*"
- HTTP -> HTTPS redirection occurs
- Permissions-Policy should exist if the response is HTML
- frame-ancestors should be in CSP or X-Frame-Options should exist if the response is HTML
- X-Content-Type-options should be "nosniff"
- Referrer-Policy should be set
- X-XSS-Protection should be set to "1; mode=block"
- HTML should start with "<!doctype html>"
- <html> tag should include lang
- HTML should include meta charset tag
- HTML should include <title>
- HTML should include link with rel="icon"
- HTML should not use schemeless urls for links or hrefs
- All script tags should use subresource integrity
- X-DNS-Prefetch-Control should be set to off
- CDNs should not be used for Javascript or CSS assets
- Content-Security-Policy header should exist
- Content-Security-Policy header should start with default-src 'none'
- Content-Security-Policy header must not include unsafe-inline
- Content-Security-Policy header must not include unsafe-eval
- Content-Security-Policy header should include report-uri
- Content-Security-Policy header should include report-to
- Content-Security-Policy header should include upgrade-insecure-requests
- Content-Security-Policy header only includes valid directives
- At least two nameservers should be configured
- Cross-Origin-Resource-Policy should be "same-origin"
- cross-origin-opener-policy should be "same-origin"
- Cross-Origin-Embedder-Policy should be "require-corp"
- Report-To Header should be included in response
- Response should include a Content-Type
- Response should be gzipped
- Content-Type header should contain charset
- Expires header is depreciated and should not be returned
- Cache-Control header should be included in the response
- SPF TXT record should exist
- SPF TXT record should contain "-all"
- SPF DNS record is depreciated and should not exist
- SPF includes use less than 10 DNS requests
- DMARC record should exist
- Expect-CT header is in the response
- Expect-CT header should include report-uri
- Robots.txt exists and is a text file
- Security.txt exists and is a text file that contains required attributes
- Favicon is served at /favicon.ico
- Headers that leak information should not be in the response
- SSL certificate should be trusted
- SSL expiry should be less than one year
- SSL expiry should be greater than five days
- SSL connection fails when using TLS 1.1
- SSL connection fails when using TLS 1.0
- DNS CAA should be enabled
- Response should be a 200 (after redirects)


### Potential / WIP

- GraphQL introspection is not enabled
- DNSSEC is supported
- DKIM is configured
- SPF must not contain +all or ?all
- SPF must contain "all" (otherwise it defaults to ?all)
- DMARC contains "p=quarantine" or "p=reject"
- DMARC / SPF configuration when there is no MX record
- CSP should contain default-src or script-src (there's no XSS protection by default)


## Not in scope

Some things are best left to other tools, or are generally handled in other ways by web development teams.

- Dependency scanning. Use a service to regularly check that you are using the latest version of your dependencies.
- Vulnerability scanning. This tool doesn't replace a penetration test, or automated penetration testing tools.
- Scans for specific CMSs (i.e. Wordpress, Drupal, etc.). You know what CMS you are using, and you should run framework/cms specific tools in addition to this.


## Standard Checks

- https://internet.nl/
- https://www.ssllabs.com/ssltest/
- https://securityheaders.com/
- https://csp-evaluator.withgoogle.com/
- https://observatory.mozilla.org/
- https://screenshots.page/ (IPv6 screenshots)
- https://tools.pingdom.com/
