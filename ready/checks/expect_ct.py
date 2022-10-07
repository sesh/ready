from ready.result import result


# Check: Expect-CT header is in the response
# NOTE: Expect-CT is deprecated
def check_expect_ct_header_should_exist_in_response(responses, **kwargs):
    return result(
        responses["response"].headers.get("expect-ct") != None,
        f"Expect-CT header is in the response ({responses['response'].headers.get('expect-ct')})",
        "expect_ct",
        warn_on_fail=True,
        **kwargs,
    )


# Check: Expect-CT header should include report-uri
def check_expect_ct_header_should_include_report_uri(responses, **kwargs):
    return result(
        "report-uri=" in responses["response"].headers.get("expect-ct", ""),
        f"Expect-CT header should include report-uri ({responses['response'].headers.get('expect-ct')})",
        "expect_ct_report_uri",
        warn_on_fail=True,
        **kwargs,
    )
