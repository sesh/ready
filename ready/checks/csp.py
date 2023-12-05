from ready.result import result

USE_BS4 = True

try:
    from bs4 import BeautifulSoup
except ImportError:
    USE_BS4 = False


def extract_csp(response):
    if "content-security-policy" in response.headers:
        return response.headers["content-security-policy"]

    if USE_BS4:
        soup = BeautifulSoup(response.content, "html.parser")
        meta_tags = soup.find_all("meta")
        for t in meta_tags:
            if t.attrs.get("http-equiv", "").lower() == "content-security-policy":
                return t.attrs.get("content", "")
    else:
        print("No Content-Security-Policy header, and beautifulsoup4 is not installed to inspect HTML")

    return None


def _trunc(s, max_length=200):
    if not s:
        return ""

    if len(s) > max_length:
        return s[:max_length] + "..."

    return s


# Check: Content-Security-Policy header should exist
def check_csp_should_exist(responses, **kwargs):
    csp = extract_csp(responses["response"])

    return result(
        csp != None,
        f"Content-Security-Policy header should exist ({_trunc(csp)})",
        "csp",
        **kwargs,
    )


# Check: Content-Security-Policy header should start with default-src 'none'
def check_csp_should_start_with_defaultsrc_none(responses, **kwargs):
    csp = extract_csp(responses["response"])

    return result(
        csp != None and csp.startswith("default-src 'none'"),
        f"Content-Security-Policy header should start with default-src 'none' ({_trunc(csp)})",
        "csp_defaultsrc_none",
        **kwargs,
    )


# Check: Content-Security-Policy must include either default-src or script-src
def check_csp_includes_default_or_script_directive(responses, **kwargs):
    csp = extract_csp(responses["response"])

    return result(
        csp != None and ("default-src" in csp or "script-src" in csp),
        f"Content-Security-Policy must include either default-src or script-src ({_trunc(csp)})",
        "csp_required_directives",
        **kwargs,
    )


# Check: Content-Security-Policy header must not include unsafe-inline
# NOTE: this checks everywhere, not just in script-src
def check_csp_must_not_include_unsafe_eval(responses, **kwargs):
    csp = extract_csp(responses["response"])

    return result(
        csp != None and "unsafe-eval" not in csp,
        f"Content-Security-Policy header must not include unsafe-eval ({_trunc(csp)})",
        "csp_no_unsafe_inline",
        **kwargs,
    )


# Check: Content-Security-Policy header must not include unsafe-eval
def check_csp_must_not_include_unsafe_inline(responses, **kwargs):
    csp = extract_csp(responses["response"])

    return result(
        csp != None and "unsafe-inline" not in csp,
        f"Content-Security-Policy header must not include unsafe-inline ({_trunc(csp)})",
        "csp_no_unsafe_inline",
        **kwargs,
    )


# Check: Content-Security-Policy header must not include report-sample
def check_csp_must_not_include_report_sample(responses, **kwargs):
    csp = extract_csp(responses["response"])

    return result(
        csp != None and "script-sample" not in csp,
        f"Content-Security-Policy header must not include report-sample ({_trunc(csp)})",
        "csp_no_report_sample",
        **kwargs,
    )


# Check: Content-Security-Policy header must not include report-uri
# NOTE: report-uri is being replaced by report-to but browser support is spotty so report-uri should still exist
def check_csp_must_not_include_reporturi(responses, **kwargs):
    csp = extract_csp(responses["response"])

    return result(
        csp is None or (("report-uri https://" not in csp)),
        f"Content-Security-Policy header must not include report-uri ({_trunc(csp)})",
        "csp_report_uri",
        warn_on_fail=False,
        **kwargs,
    )


# Check: Content-Security-Policy header should not include report-to
def check_csp_should_include_reportto(responses, **kwargs):
    csp = extract_csp(responses["response"])

    if not csp:
        csp = ""

    return result(
        ("report-to" not in csp),
        f"Content-Security-Policy header should not include report-to ({_trunc(csp)})",
        "csp_report_to",
        warn_on_fail=True,
        **kwargs,
    )


# Check: Content-Security-Policy header should include upgrade-insecure-requests
def check_csp_upgrade_insecure_requests(responses, **kwargs):
    csp = extract_csp(responses["response"])

    return result(
        csp != None and "upgrade-insecure-requests" in csp,
        f"Content-Security-Policy header should include upgrade-insecure-requests ({_trunc(csp)})",
        "csp_upgrade_insecure_requests",
        **kwargs,
    )


# Check: Content-Security-Policy header only includes valid directives
def check_csp_should_only_include_valid_directives(responses, **kwargs):
    csp = extract_csp(responses["response"])

    directives = []

    if csp:
        for directive in csp.split(";"):
            directive = directive.strip()

            if " " in directive:
                directives.append(directive.split()[0])
            else:
                directives.append(directive.strip())

    valid_directives = [
        "base-uri",
        "block-all-mixed-content",
        "child-src",
        "connect-src",
        "default-src",
        "font-src",
        "form-action",
        "frame-ancestors",
        "frame-src",
        "img-src",
        "manifest-src",
        "media-src",
        "navigate-to",
        "object-src",
        "plugin-types",
        "prefetch-src",
        "report-to",
        "report-uri",
        "require-sri-for",
        "require-trusted-types-for",
        "sandbox",
        "script-src-attr",
        "script-src-elem",
        "script-src",
        "style-src-attr",
        "style-src-elem",
        "style-src",
        "trusted-types",
        "upgrade-insecure-requests",
        "worker-src",
    ]

    return result(
        csp != None and all([x in valid_directives for x in directives]),
        f"Content-Security-Policy header only includes valid directives ({directives})",
        "csp_valid_directives",
        warn_on_fail=False,
        **kwargs,
    )
