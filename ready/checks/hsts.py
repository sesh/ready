import re

from ready.result import result


# Check: HSTS Header should be included in response
def check_hsts_header_should_be_included_in_response(responses, **kwargs):
    return result(
        responses["response"].headers.get("strict-transport-security") != None,
        f"HSTS Header should be included in response ({responses['response'].headers.get('strict-transport-security')})",
        "ssl_hsts",
        **kwargs,
    )


# Check: HSTS Header should have a long max-age
def check_hsts_header_should_have_a_long_max_age(responses, **kwargs):
    try:
        hsts = responses["response"].headers.get("strict-transport-security", "")
        max_age_re = re.compile(r"max-age=(\d+)", re.IGNORECASE)
        m = max_age_re.match(hsts)
        max_age = int(m.groups()[0])
        if max_age < 31536000:
            raise Exception
        return result(
            True,
            f"HSTS Header should have a long max-age ({hsts})",
            "ssl_hsts_duration",
            **kwargs,
        )
    except:
        return result(
            False,
            f"HSTS Header should have a long max-age ({hsts})",
            "ssl_hsts_duration",
            **kwargs,
        )


# Check: HSTS Header should have includeSubdomains
def check_hsts_header_should_have_includesubdomains(responses, **kwargs):
    hsts = responses["response"].headers.get("strict-transport-security", "")

    # this check uses the response from the Apex/Second level domain if it fails for the
    # provided domain. See: https://github.com/sesh/ready/issues/22
    if "includesubdomains" not in hsts.lower() and responses.get("response_fld"):
        hsts = responses["response_fld"].headers.get("strict-transport-security", "") + " (from apex domain)"

    return result(
        "includesubdomains" in hsts.lower(),
        f"HSTS Header should have includeSubDomains ({hsts})",
        "ssl_hsts_subdomains",
        **kwargs,
    )


# Check: HSTS Header should have preload
def check_hsts_header_should_have_preload(responses, **kwargs):
    hsts = responses["response"].headers.get("strict-transport-security", "")

    # this check use the response from the Apex/Second Level domain if it exists
    # instead of any subdomains. See: https://github.com/sesh/ready/issues/22
    if responses.get("response_fld"):
        hsts = responses["response_fld"].headers.get("strict-transport-security", "") + " (from apex domain)"

    return result(
        "preload" in hsts.lower() and "includesubdomains" in hsts.lower(),
        f"HSTS Header should have preload and includeSubDomains ({hsts})",
        "ssl_hsts_preload",
        **kwargs,
    )
