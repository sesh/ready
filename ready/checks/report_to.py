import re

from ready.result import result


# Check: Report-To Header should be included in response
def check_report_to_header_should_be_included_in_response(responses, **kwargs):
    return result(
        responses["response"].headers.get("report-to") != None,
        f"Report-To Header should be included in response ({responses['response'].headers.get('report-to')})",
        "report_to",
        warn_on_fail=True,
        **kwargs,
    )
