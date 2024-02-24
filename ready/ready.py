import datetime
import json
import os
import sys
import urllib

from importlib import resources
from . import checks as checks_module


from ready.checks.bad_response import (
    check_bad_response_cloudflare,
    check_bad_response_kasada,
)
from ready.checks.content import (
    check_http_cache_control_is_included,
    check_http_content_type_header_contains_charset,
    check_http_expires_header_is_not_set,
    check_http_p3p_header_is_not_set,
    check_http_response_should_be_gzipped,
    check_http_response_should_include_content_type,
)
from ready.checks.cookies import (
    check_cookies_should_be_httponly,
    check_cookies_should_be_samesite,
    check_cookies_should_be_secure,
)
from ready.checks.corp_coop_coep import (
    check_cross_origin_embedder_policy_should_be_require_corp,
    check_cross_origin_opener_policy_should_be_sameorigin,
    check_cross_origin_resource_policy_should_be_sameorigin,
)
from ready.checks.csp import (
    check_csp_includes_default_or_script_directive,
    check_csp_must_not_include_report_sample,
    check_csp_must_not_include_unsafe_eval,
    check_csp_must_not_include_unsafe_inline,
    check_csp_should_exist,
    check_csp_should_include_reportto,
    check_csp_must_not_include_reporturi,
    check_csp_should_only_include_valid_directives,
    check_csp_should_start_with_defaultsrc_none,
    check_csp_upgrade_insecure_requests,
)
from ready.checks.dns import check_aaaa_record_exists
from ready.checks.email import (
    check_dmarc_record_should_exist,
    check_dmarc_record_should_reject_failures,
    check_spf_dash_all,
    check_spf_dns_record_does_not_exist,
    check_spf_record_should_exist,
    check_spf_txt_record_should_disallow_all,
    check_spf_uses_less_than_10_requests,
)
from ready.checks.hsts import (
    check_hsts_header_should_be_included_in_response,
    check_hsts_header_should_have_a_long_max_age,
    check_hsts_header_should_have_includesubdomains,
    check_hsts_header_should_have_preload,
)
from ready.checks.html import (
    check_cdns_should_not_be_used,
    check_frame_ancestors_should_exist,
    check_html_includes_rel_icon,
    check_html_includes_title,
    check_html_meta_charset,
    check_html_script_tags_use_sri,
    check_html_should_not_be_cached_for_more_than_24_hours,
    check_html_should_not_use_schemeless_urls,
    check_html_should_not_use_unnecessary_entities,
    check_html_starts_with_doctype,
    check_html_tag_includes_lang,
    check_permissions_policy_should_exist,
    check_referrer_policy_should_be_set,
    check_rss_should_return_cors_header,
    check_x_content_type_options_should_be_nosniff,
    check_x_dns_prefetch_control_is_off,
    check_x_xss_protection_should_not_exist,
)
from ready.checks.leaky_headers import check_should_not_include_leaky_headers
from ready.checks.ns import check_at_least_two_nameservers_configured
from ready.checks.redirect import check_http_to_https_redirect
from ready.checks.report_to import check_report_to_header_must_not_be_included_in_response
from ready.checks.ssl import (
    check_dns_caa_record_should_exist,
    check_dns_caa_record_should_include_accounturi,
    check_dns_caa_record_should_include_validationmethods,
    check_ssl_certificate_should_be_trusted,
    check_ssl_connection_fails_with_tls_1_0,
    check_ssl_connection_fails_with_tls_1_1,
    check_ssl_expiry_should_be_greater_than_five_days,
    check_ssl_expiry_should_be_less_than_one_year,
)
from ready.checks.status import check_http_response_should_be_200
from ready.checks.swagger import check_swagger_should_not_return_200
from ready.checks.well_known import (
    check_favicon_is_served,
    check_robots_txt_exists,
    check_security_txt_exists,
    check_security_txt_not_expired,
)
from ready.thttp import pretty, request

USE_FLD = True

try:
    from tld import get_fld
except ImportError:
    USE_FLD = False


DEFAULT_HEADERS = {
    # MacOS Safari
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-AU,en;q=0.9",
    "accept-encoding": "gzip",
}


def response_or_none(url, name="", request_filter="", **kwargs):
    if request_filter and request_filter not in name:
        print(f"Skipping HTTP request {name}")
        return None

    try:
        response = request(url, **kwargs)
        return response
    except urllib.error.URLError:
        return None
    except Exception as e:
        print(url, type(e))
        return None


def ready(
    domain,
    print_headers=False,
    print_content=False,
    json_output=False,
    hide_output=False,
    fuzz=False,
    check_filter=None,
    request_filter=None,
    extra_args={},
):
    domain_with_no_path = urllib.parse.urlparse("https://" + domain).hostname

    if USE_FLD:
        fld = get_fld(domain, fix_protocol=True)
    else:
        fld = "Disabled. Install tld if fld is different to domain."

    print(f"Domain: {domain}, Domain (no path): {domain_with_no_path}, First Level Domain: {fld}")

    responses = {
        "http_response": response_or_none(
            f"http://{domain}", "http_response", request_filter, verify=False, headers=DEFAULT_HEADERS, timeout=3
        ),
        "response": response_or_none(
            f"https://{domain}", "response", request_filter, verify=False, headers=DEFAULT_HEADERS, timeout=3
        ),
    }

    if not responses["response"]:
        print(f"No response from https://{domain}")

        if request_filter:
            print("Request filter in place, continuing...")
        else:
            return None

    responses["security_txt_response"] = response_or_none(
        f"https://{domain_with_no_path}/.well-known/security.txt",
        "security_txt_response",
        request_filter,
        headers=DEFAULT_HEADERS,
        timeout=3,
    )

    responses["robots_txt_response"] = response_or_none(
        f"https://{domain_with_no_path}/robots.txt", "robots_txt_response", request_filter, headers=DEFAULT_HEADERS, timeout=3
    )

    responses["favicon_response"] = response_or_none(
        f"https://{domain_with_no_path}/favicon.ico",
        "favicon_response",
        request_filter,
        verify=False,
        headers=DEFAULT_HEADERS,
        timeout=3,
    )

    responses["dns_ns_response"] = response_or_none(
        f"https://dns.google/resolve?name={domain_with_no_path}&type=NS", "dns_ns_response", request_filter
    )
    responses["dns_mx_response"] = response_or_none(
        f"https://dns.google/resolve?name={domain_with_no_path}&type=MX", "dns_mx_response", request_filter
    )
    responses["dns_txt_response"] = response_or_none(
        f"https://dns.google/resolve?name={domain_with_no_path}&type=TXT", "dns_txt_response", request_filter
    )
    responses["dns_spf_response"] = response_or_none(
        f"https://dns.google/resolve?name={domain_with_no_path}&type=SPF", "dns_spf_response", request_filter
    )
    responses["dns_caa_response"] = response_or_none(
        f"https://dns.google/resolve?name={domain_with_no_path}&type=CAA", "dns_caa_response", request_filter
    )
    responses["dns_a_response"] = response_or_none(
        f"https://dns.google/resolve?name={domain_with_no_path}&type=A", "dns_aaaa_response", request_filter
    )
    responses["dns_aaaa_response"] = response_or_none(
        f"https://dns.google/resolve?name={domain_with_no_path}&type=AAAA", "dns_aaaa_response", request_filter
    )
    responses["dns_dmarc_response"] = response_or_none(
        f"https://dns.google/resolve?name=_dmarc.{domain_with_no_path}&type=TXT", "dns_dmarc_response", request_filter
    )

    if USE_FLD and domain != fld:
        responses["dns_ns_response_fld"] = response_or_none(f"https://dns.google/resolve?name={fld}&type=NS")
        responses["dns_mx_response_fld"] = response_or_none(f"https://dns.google/resolve?name={fld}&type=MX")
        responses["dns_spf_response_fld"] = response_or_none(f"https://dns.google/resolve?name={fld}&type=SPF")
        responses["dns_txt_response_fld"] = response_or_none(f"https://dns.google/resolve?name={fld}&type=TXT")
        responses["dns_dmarc_response_fld"] = response_or_none(f"https://dns.google/resolve?name=_dmarc.{fld}&type=TXT")
        responses["dns_caa_response_fld"] = response_or_none(f"https://dns.google/resolve?name={fld}&type=CAA")

    checks = []
    is_html = responses["response"] and "html" in responses["response"].headers.get("content-type", "")

    a_records = [x["data"] for x in responses["dns_a_response"].json.get("Answer", [])]
    aaaa_records = [x["data"] for x in responses["dns_aaaa_response"].json.get("Answer", [])]
    extra_args["is_ipv6"] = len(a_records) == 0 and len(aaaa_records) > 0

    # TODO: accept argument to _not_ print to stdout
    if print_headers:
        pretty(responses["response"], content=False)
        print()

    if print_content:
        print(responses["response"].content)

    # bad response checks go first
    checks = [
        check_bad_response_kasada,
        check_bad_response_cloudflare,
    ]

    checks.extend(
        [
            check_http_to_https_redirect,
            check_http_response_should_be_200,
            check_http_response_should_include_content_type,
            check_aaaa_record_exists,
            check_hsts_header_should_be_included_in_response,
            check_hsts_header_should_have_a_long_max_age,
            check_hsts_header_should_have_includesubdomains,
            check_hsts_header_should_have_preload,
            check_csp_should_exist,
            check_csp_should_start_with_defaultsrc_none,
            check_csp_includes_default_or_script_directive,
            check_csp_must_not_include_unsafe_inline,
            check_csp_must_not_include_unsafe_eval,
            check_csp_must_not_include_report_sample,
            check_csp_upgrade_insecure_requests,
            check_csp_must_not_include_reporturi,
            check_csp_should_include_reportto,
            check_csp_should_only_include_valid_directives,
            check_report_to_header_must_not_be_included_in_response,
            check_robots_txt_exists,
            check_security_txt_exists,
            check_security_txt_not_expired,
            check_favicon_is_served,
            check_http_response_should_be_gzipped,
            check_http_content_type_header_contains_charset,
            check_http_expires_header_is_not_set,
            check_http_cache_control_is_included,
            check_http_p3p_header_is_not_set,
            check_referrer_policy_should_be_set,
            check_cross_origin_resource_policy_should_be_sameorigin,
            check_cross_origin_opener_policy_should_be_sameorigin,
            check_cross_origin_embedder_policy_should_be_require_corp,
            check_should_not_include_leaky_headers,
            check_ssl_expiry_should_be_less_than_one_year,
            check_ssl_expiry_should_be_greater_than_five_days,
            check_ssl_certificate_should_be_trusted,
            check_ssl_connection_fails_with_tls_1_1,
            check_ssl_connection_fails_with_tls_1_0,
            check_dns_caa_record_should_exist,
            check_dns_caa_record_should_include_accounturi,
            check_dns_caa_record_should_include_validationmethods,
            check_at_least_two_nameservers_configured,
            check_cookies_should_be_samesite,
            check_cookies_should_be_secure,
            check_cookies_should_be_httponly,
            check_spf_dash_all,
            check_spf_record_should_exist,
            check_spf_dns_record_does_not_exist,
            check_spf_txt_record_should_disallow_all,
            check_dmarc_record_should_exist,
            check_dmarc_record_should_reject_failures,
            check_spf_uses_less_than_10_requests,
        ]
    )

    if is_html:
        checks.extend(
            [
                check_permissions_policy_should_exist,
                check_frame_ancestors_should_exist,
                check_x_content_type_options_should_be_nosniff,
                check_x_xss_protection_should_not_exist,
                check_html_starts_with_doctype,
                check_html_tag_includes_lang,
                check_html_meta_charset,
                check_html_includes_title,
                check_html_includes_rel_icon,
                check_html_should_not_use_schemeless_urls,
                check_html_script_tags_use_sri,
                check_html_should_not_use_unnecessary_entities,
                check_html_should_not_be_cached_for_more_than_24_hours,
                check_x_dns_prefetch_control_is_off,
                check_cdns_should_not_be_used,
                check_rss_should_return_cors_header,
            ]
        )

    if fuzz:
        checks.extend(
            [
                check_swagger_should_not_return_200,
            ]
        )

    extra_args["print_output"] = not hide_output

    results = []
    for c in checks:
        if check_filter and check_filter not in c.__name__:
            continue

        result = c(responses, domain=domain, domain_with_no_path=domain_with_no_path, **extra_args)
        if result:
            results.append(result)

    if json_output:
        print(
            json.dumps(
                {
                    "domain": domain,
                    "score": score_from_results(results),
                    "checks": {
                        r.check: {
                            "passed": r.passed,
                            "message": r.message,
                        }
                        for r in results
                    },
                    "when": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
                indent=2,
            )
        )

    return results


def score_from_results(results):
    return 100 - 3 * len([x for x in results if not x.passed and not x.warn_on_fail])


def parse_args(args):
    result = {
        a.split("=")[0]: (
            int(a.split("=")[1]) if "=" in a and a.split("=")[1].isnumeric() else a.split("=")[1] if "=" in a else True
        )
        for a in args
        if "--" in a
    }
    result["[]"] = [a for a in args if not a.startswith("--")]
    return result


def usage():
    print("ready")
    print("")
    print("Usage: ready.py [--headers] [--content] [--json] [--quiet] [--score] [--fuzz] <domain>")
    print("")
    print("  --headers      Output the headers from the HTTPS request made to the domain")
    print("  --content      Output the content from the HTTPS request made to the domain")
    print("  --fuzz         Include checks that fuzz urls (only run this on your own domain)")
    print("  --json         Provide JSON output")
    print("  --quiet        No text output")
    print("  --score        Print a score out of 100 for this domain")
    print("  --doc          Print the list of check names")

    print("\nDevelopment / experimental options for filtering checks and HTTP requests during testing:")
    print("")
    print("  --check-filter=<x>     Only run checks that match the provided filter")
    print("  --request-filter=<x>   Only make HTTP requests that match the provided filter")


def cli():
    args = parse_args(sys.argv[1:])

    if "--doc" in args:
        for f in resources.files(checks_module).iterdir():
            if f.name.endswith(".py"):
                for line in open(f).readlines():
                    if line.strip().startswith("# Check: "):
                        print(line.strip().replace("# Check: ", "- "))
        sys.exit()

    if "--help" in args or not args["[]"]:
        usage()
        sys.exit()

    results = ready(
        args["[]"][0],
        print_headers=args.get("--headers", False),
        print_content=args.get("--content", False),
        json_output=args.get("--json", False),
        hide_output=args.get("--quiet", False),
        fuzz=args.get("--fuzz", False),
        check_filter=args.get("--check-filter", ""),
        request_filter=args.get("--request-filter", ""),
    )

    if "--score" in args:
        print(f"Score: {score_from_results(results)}/100")


if __name__ == "__main__":
    cli()
