import re
from urllib.parse import urljoin

from ready import thttp
from ready.checks.csp import extract_csp
from ready.result import result

USE_BS4 = True

try:
    from bs4 import BeautifulSoup
except ImportError:
    USE_BS4 = False


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
        responses["response"].headers.get("x-frame-options") != None or (csp != None and "frame-ancestors" in csp),
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


# Check: X-XSS-Protection header should not exist
def check_x_xss_protection_should_not_exist(responses, **kwargs):
    return result(
        "x-xss-protection" not in responses["response"].headers,
        f'X-XSS-Protection header should not exist" ({responses["response"].headers.get("x-xss-protection")})',
        "html_x_xss_protection_not_set",
        warn_on_fail=True,
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


# Check: HTML should not use unnecessary HTML entities
def check_html_should_not_use_unnecessary_entities(responses, **kwargs):
    allow_list = [b"nbsp", b"amp", b"quot", b"lt", b"gt"]

    # The longest entity on the registered entity list is "CounterClockwiseContourIntegral"
    # https://html.spec.whatwg.org/entities.json
    entities = re.findall(b"&([\w#]{1,32});", responses["response"].content)
    entities = [e for e in entities if e not in allow_list]

    return result(
        len(entities) == 0,
        f"HTML should not use unnecessary HTML entities ({[e.decode() for e in set(entities)]})",
        "html_unnecessary_entities",
        warn_on_fail=True,
        **kwargs,
    )
    print(entities)


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
    if USE_BS4:
        feed_urls = []
        feed_types = [
            "application/rss+xml",
            "application/feed+json",
        ]

        soup = BeautifulSoup(responses["response"].content, features="html.parser")

        links = soup.find_all("link")

        for link in links:
            if "alternate" in link.attrs.get("rel", ""):
                if link.attrs.get("type", "") in feed_types:
                    feed_urls.append(urljoin(responses["response"].url, link.attrs.get("href")))

        cors_values = []
        for url in feed_urls:
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = responses["response"].url.rstrip("/") + url

            if url.startswith("http"):
                response = thttp.request(url)
                cors_values.append(response.headers.get("access-control-allow-origin"))

        return result(
            all([x is not None for x in cors_values]),
            f"RSS and JSON feeds should return Access-Control-Allow-Origin header ({', '.join(feed_urls) if feed_urls else 'no feeds'})",
            "feeds_cors_enabled",
            **kwargs,
        )
    else:
        return result(
            False,
            f"RSS and JSON feeds should return Access-Control-Allow-Origin header (skipped because beautifulsoup is missing)",
            "feeds_cors_enabled",
            warn_on_fail=True,
            **kwargs,
        )


# Check: Cache-Control max-age should be <= 86400 for HTML documents
def check_html_should_not_be_cached_for_more_than_24_hours(responses, **kwargs):
    cc_header = responses["response"].headers.get("cache-control", "")
    error = "no Cache-Control header"

    if "max-age=" in cc_header:
        max_age = re.search("max-age=(?P<age>\d+)", cc_header)
        if max_age:
            try:
                age = int(max_age.group("age"))
                return result(
                    age <= 86400,
                    f"Cache-Control max-age should be <= 86400 for HTML documents (parse error: {cc_header})",
                    "html_cache_duration",
                    **kwargs,
                )
            except ValueError:
                error = f"parse error: {cc_header}"
        else:
            error = f"match error: {cc_header}"

    return result(
        False,
        f"Cache-Control max-age should be <= 86400 for HTML documents ({error})",
        "html_cache_duration",
        warn_on_fail=True,
        **kwargs,
    )
