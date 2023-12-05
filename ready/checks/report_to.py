import re

from ready.result import result


# Check: Report-To Header must not be included in response
def check_report_to_header_must_not_be_included_in_response(responses, **kwargs):
    return result(
        responses["response"].headers.get("report-to") in [None, ""],
        f"Report-To Header must not be included in response ({responses['response'].headers.get('report-to')})",
        "report_to",
        **kwargs,
    )
