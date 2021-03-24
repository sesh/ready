from ready.result import result


# Check: Response should be a 200 (after redirects)
def check_http_response_should_be_200(responses, **kwargs):
    return result(
        responses["response"] and responses["response"].status == 200,
        f"Response should be a 200 ({getattr(responses['response'], 'status')} - {getattr(responses['response'], 'url')})",
        "https_status",
        **kwargs,
    )
