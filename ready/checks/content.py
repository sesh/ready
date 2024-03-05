from ready.result import result


# Check: Response should include a Content-Type
def check_http_response_should_include_content_type(responses, **kwargs):
    return result(
        responses["response"].headers.get("content-type") != None,
        f"Response should include a Content-Type ({responses['response'].headers.get('content-type')})",
        "http_content_type",
        **kwargs,
    )


# Check: Response should be gzipped
def check_http_response_should_be_gzipped(responses, **kwargs):
    return result(
        "gzip" in responses["response"].headers.get("content-encoding", ""),
        f"Response should be gzipped ({responses['response'].headers.get('content-encoding', '')})",
        "http_gzipped",
        **kwargs,
    )


# Check: Content-Type header should contain charset
def check_http_content_type_header_contains_charset(responses, **kwargs):
    return result(
        "charset=" in responses["response"].headers.get("content-type", ""),
        f'Content-Type header should contain charset ({responses["response"].headers.get("content-type", "")})',
        "http_charset",
        **kwargs,
    )


# Check: Expires header should not be used without Cache-Control
def check_http_expires_header_not_used_without_cache_control(responses, **kwargs):
    # see: https://github.com/sesh/ready/issues/24
    # nginx sets Cache-Control and Expires on documents
    # this test should:
    #   - pass if Expires is unset
    #   - pass if both Expires and Cache-Control are set
    #   - fail in all other scenarios

    expires = responses['response'].headers.get('expires')
    cache_control = {responses['response'].headers.get('cache-control')}

    check_passed = False
    if not expires or (expires and cache_control):
        check_passed = True

    return result(
        check_passed,
        f"Expires header should not be used without Cache-Control (Expires: {expires}, Cache-Control: {cache_control})",
        "http_expires",
        **kwargs,
    )


# Check: Cache-Control header should be included in the response
def check_http_cache_control_is_included(responses, **kwargs):
    return result(
        "cache-control" in responses["response"].headers,
        f"Cache-Control header should be included in the response ({responses['response'].headers.get('cache-control')})",
        "http_expires",
        **kwargs,
    )


# Check: P3P header is deprecated and should not be returned
def check_http_p3p_header_is_not_set(responses, **kwargs):
    return result(
        "p3p" not in responses["response"].headers,
        f"P3P header is deprecated and should not be returned ({responses['response'].headers.get('p3p')})",
        "http_p3p",
        **kwargs,
    )
