from ready.result import result


# Check: Cookies should set the SameSite flag
def check_cookies_should_be_samesite(responses, **kwargs):
    cookies = responses["response"].headers.get("set-cookie", "")
    cookie_note = cookies or "no cookie set"

    return result(
        not cookies or "samesite=" in cookies.lower(),
        f"Cookies should set the SameSite flag ({cookie_note})",
        "cookies_samesite",
        **kwargs,
    )


# Check: Cookies should set the Secure flag
def check_cookies_should_be_secure(responses, **kwargs):
    cookies = responses["response"].headers.get("set-cookie", "")
    cookie_note = cookies or "no cookie set"

    return result(
        not cookies or "secure;" in cookies.lower(),
        f"Cookies should set the Secure flag ({cookie_note})",
        "cookies_secure",
        **kwargs,
    )


# Check: Cookies should set the HttpOnly flag
def check_cookies_should_be_httponly(responses, **kwargs):
    cookies = responses["response"].headers.get("set-cookie", "")
    cookie_note = cookies or "no cookie set"

    return result(
        not cookies or "httponly;" in cookies.lower(),
        f"Cookies should set the HttpOnly flag ({cookie_note})",
        "cookies_httponly",
        **kwargs,
    )
