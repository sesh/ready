import re

from ready.result import result


# Check: Response should not contain hints of a Cloudflare captcha page
def check_bad_response_cloudflare(responses, **kwargs):
    return result(
        'div id="cf-content"' not in responses["response"].content.decode(errors="ignore"),
        f"Response should not contain hints of a Cloudflare captcha page",
        "bad_cloudflare",
        warn_on_fail=True,
        **kwargs,
    )


# Check: Response should not contain hints of a Kasada error page
def check_bad_response_kasada(responses, **kwargs):
    uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    failing = False

    if responses["response"].status == 429:
        if re.search(uuid_pattern + r"/" + uuid_pattern, responses["response"].content.decode(errors="ignore")):
            failing = True

    return result(
        not failing,
        f"Response should not contain hints of a Kasada error page",
        "bad_kasada",
        warn_on_fail=True,
        **kwargs,
    )
