import json

from ready.result import result


# Check: An AAAA DNS record exists (IPv6 Support)
def check_aaaa_record_exists(responses, **kwargs):
    records = [x["data"] for x in responses["dns_aaaa_response"].json.get("Answer", [])]

    return result(
        len(records) >= 1,
        f"An AAAA DNS record exists ({records})",
        "dns_aaaa",
        **kwargs,
    )
