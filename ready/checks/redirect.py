from ready.result import result


# Check: HTTP -> HTTPS redirection occurs
def check_http_to_https_redirect(responses, **kwargs):
    if responses["http_response"]:
        return result(
            responses["http_response"].url.startswith("https://"),
            f"HTTP -> HTTPS redirection ({responses['http_response'].url})",
            "redirect_http",
            **kwargs,
        )

    return result(
        False,
        f"HTTP -> HTTPS redirection (no HTTP response)",
        "redirect_http",
        warn_on_fail=True,
        **kwargs,
    )
