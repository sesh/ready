from ready.result import result


# Check: Cross-Origin-Resource-Policy should be "same-origin"
def check_cross_origin_resource_policy_should_be_sameorigin(responses, **kwargs):
    return result(
        responses["response"].headers.get("cross-origin-resource-policy", "") == "same-origin",
        f"Cross-Origin-Resource-Policy header should be same-origin ({responses['response'].headers.get('cross-origin-resource-policy')})",
        "http_corp",
        warn_on_fail=True,
        **kwargs,
    )


# Check: cross-origin-opener-policy should be "same-origin"
def check_cross_origin_opener_policy_should_be_sameorigin(responses, **kwargs):
    return result(
        responses["response"].headers.get("cross-origin-opener-policy", "") == "same-origin",
        f"Cross-Origin-Opener-Policy header should be same-origin ({responses['response'].headers.get('cross-origin-opener-policy')})",
        "http_coop",
        warn_on_fail=True,
        **kwargs,
    )


# Check: Cross-Origin-Embedder-Policy should be "require-corp"
def check_cross_origin_embedder_policy_should_be_require_corp(responses, **kwargs):
    return result(
        responses["response"].headers.get("cross-origin-embedder-policy", "") == "require-corp",
        f"Cross-Origin-Embedder-Policy header should be require-corp ({responses['response'].headers.get('cross-origin-embedder-policy')})",
        "http_coep",
        warn_on_fail=True,
        **kwargs,
    )
