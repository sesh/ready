import re

from ready.checks.csp import extract_csp
from ready.result import result
from ready import thttp


# Check: Permissions-Policy should exist if the response is HTML
def check_permissions_policy_should_exist(responses, **kwargs):
    return result(
        responses["response"].headers.get("permissions-policy") != None,
        f"Permissions-Policy should exist if the response is HTML ({responses['response'].headers.get('permissions-policy')})",
        "html_permissions_policy",
        **kwargs,
    )


# Check: frame-ancestors should be in CSP or X-Frame-Options should exist if the response is HTML
def check_frame_ancestors_should_exist(responses, **kwargs):
    csp = extract_csp(responses["response"])
    return result(
        responses["response"].headers.get("x-frame-options") != None or (csp and "frame-ancestors" in csp),
        f"frame-ancestors should be in CSP or X-Frame-Options should exist if the response is HTML (X-Frame-Options: {responses['response'].headers.get('x-frame-options')}, CSP: {csp})",
        "html_frame_ancestors",
        **kwargs,
    )


# Check: X-Content-Type-options should be "nosniff"
def check_x_content_type_options_should_be_nosniff(responses, **kwargs):
    return result(
        responses["response"].headers.get("x-content-type-options", "") == "nosniff",
        f'X-Content-Type-options should be "nosniff" ({responses["response"].headers.get("x-content-type-options", "")})',
        "html_x_content_type_options_nosniff",
        **kwargs,
    )


# Check: Referrer-Policy should be set
def check_referrer_policy_should_be_set(responses, **kwargs):
    return result(
        responses["response"].headers.get("referrer-policy") != None,
        f'Referrer-Policy should be set ({responses["response"].headers.get("referrer-policy", "")})',
        "html_referrer_policy",
        **kwargs,
    )


# Check: X-XSS-Protection should be set to "1; mode=block"
# NOTE: required-ish for older browsers, even with a CSP
def check_x_xss_protection_should_be_set(responses, **kwargs):
    return result(
        responses["response"].headers.get("x-xss-protection") == "1; mode=block",
        f'X-XSS-Protection should be set to "1; mode=block" ({responses["response"].headers.get("x-xss-protection")})',
        "html_x_xss_protection",
        **kwargs,
    )


# Check: HTML should start with "<!doctype html>"
def check_html_starts_with_doctype(responses, **kwargs):
    return result(
        responses["response"].content.lower().strip().startswith(b"<!doctype html>"),
        f'HTML should start with "<!doctype html>"',
        "html_doctype",
        **kwargs,
    )


# Check: `<html>` tag should include lang
def check_html_tag_includes_lang(responses, **kwargs):
    if "<html" in responses["response"].content.decode(errors="ignore"):
        html_tag = responses["response"].content.decode(errors="ignore").split("<html")[1].split(">")[0].replace("'", '"')
        html_tag = "<html" + html_tag + ">"
    else:
        html_tag = "no tag"
    return result(
        "lang=" in html_tag,
        f"<html> tag should include lang ({html_tag})",
        "html_tag_includes_lang",
        **kwargs,
    )


# Check: HTML should include meta charset tag
def check_html_meta_charset(responses, **kwargs):
    return result(
        b"<meta charset=" in responses["response"].content.lower(),
        f"HTML should include meta charset tag",
        "html_meta_charset",
        **kwargs,
    )


# Check: HTML should include `<title>`
def check_html_includes_title(responses, **kwargs):
    return result(
        b"<title>" in responses["response"].content.lower(),
        f"HTML should include title",
        "html_includes_title",
        **kwargs,
    )


# Check: HTML should include link with rel="icon"
def check_html_includes_rel_icon(responses, **kwargs):
    link_re = re.compile(b"<link (.+)>")
    links = [l.replace(b"'", b'"') for l in link_re.findall(responses["response"].content)]

    return result(
        any([b'rel="icon"' in link for link in links]) or any([b'rel="shortcut icon"' in link for link in links]),
        'HTML should include link with rel="icon"',
        "html_rel_icon",
        **kwargs,
    )


# Check: HTML should not use schemeless urls for links or hrefs
def check_html_should_not_use_schemeless_urls(responses, **kwargs):
    return result(
        b'="//' not in responses["response"].content and b"='//" not in responses["response"].content,
        "HTML should not use schemeless urls for links or hrefs",
        "html_schemeless",
        **kwargs,
    )


# Check: All script tags should use subresource integrity
def check_html_script_tags_use_sri(responses, **kwargs):
    script_tags = re.findall(b"<script ([^\>]+)", responses["response"].content)

    return result(
        all([b"integrity" in tag for tag in script_tags]),
        f"All script tags should use subresource integrity",
        "html_sri_js",
        **kwargs,
    )


# Check: X-DNS-Prefetch-Control should be set to off
def check_x_dns_prefetch_control_is_off(responses, **kwargs):
    return result(
        responses["response"].headers.get("x-dns-prefetch-control", "") == "off",
        f"X-DNS-Prefetch-Control should be set to off ({responses['response'].headers.get('x-dns-prefetch-control', '')})",
        "html_x_dns_prefetch",
        **kwargs,
    )


# Check: CDNs should not be used for Javascript or CSS assets
def check_cdns_should_not_be_used(responses, **kwargs):
    # XXX: This list was compiled by myself from a number of random web sources, if a better maintained list
    # exists then I would love to replace this
    cdn_domains = [
        "cdn.jsdelivr.net",
        "cdn.statically.io",
        "bootstrapcdn.com",
        "cdnjs.cloudflare.com",
        "sentry-cdn.com",
        "ajax.googleapis.com",
        "code.jquery.com",
        "ajax.aspnetcdn.com",
    ]

    script_tags = re.findall(b"<script ([^\>]+)", responses["response"].content)
    link_tags = re.findall(b"<link (.+)>", responses["response"].content)

    for tag in script_tags + link_tags:
        if any([x in tag.decode() for x in cdn_domains]):
            return result(False, "CDNs should not be used for Javascript or CSS assets", "html_cdn_usage", **kwargs)

    return result(True, "CDNs should not be used for Javascript or CSS assets", "html_cdn_usage", **kwargs)


# Check: RSS and JSON feeds should return Access-Control-Allow-Origin header
def check_rss_should_return_cors_header(responses, **kwargs):
    feed_types = [
        'application/rss+xml',
        'application/feed+json',
    ]

    link_tags = re.findall(b"<link (.+)>", responses["response"].content)
    feed_urls = []

    for tag in link_tags:
        tag = tag.decode().replace("\'", "\"")
        if 'rel="alternate"' in tag:
            if any([f in tag for f in feed_types]):
                link = re.search("href\=\"(.+)\"", tag)
                if link:
                    url = link.groups()[0]
                    feed_urls.append(url)

    cors_values = []
    for url in feed_urls:
        if url.startswith("//"):
            url = "https:" + url
        elif url.startswith("/"):
            url = responses["response"].url.rstrip("/") + url

        response = thttp.request(url)
        cors_values.append(response.headers.get('access-control-allow-origin'))

    return result(
        all([x is not None for x in cors_values]),
        f"RSS and JSON feeds should return Access-Control-Allow-Origin header ({', '.join(feed_urls)})",
        "feeds_cors_enabled",
        **kwargs
    )

