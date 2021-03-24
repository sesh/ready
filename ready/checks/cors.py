from ready.result import result


# Check: Access-Control-Allow-Origin header is in the response
def check_expect_access_control_allow_origin_in_response(responses, **kwargs):
    return result(
        responses["response"].headers.get("access-control-allow-origin") != None,
        f"Access-Control-Allow-Origin header is in the response ({responses['response'].headers.get('access-control-allow-origin')})",
        "cors_header_exists",
        **kwargs,
    )


# Check: Access-Control-Allow-Origin is not set to "*"
def check_access_control_allow_origin_is_not_wildcard(responses, **kwargs):
    return result(
        responses["response"].headers.get("access-control-allow-origin", "") != "*",
        f"Access-Control-Allow-Origin is not set to '*' ({responses['response'].headers.get('access-control-allow-origin')})",
        "cors_header_exists",
        warn_on_fail=True,
        **kwargs,
    )
