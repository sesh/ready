from ready.result import result


# Check: At least two nameservers should be configured
def check_at_least_two_nameservers_configured(responses, **kwargs):
    nameservers = [x["data"] for x in responses["dns_ns_response"].json.get("Answer", [])]

    if not nameservers and "dns_ns_response_fld" in responses:
        nameservers = [x["data"] for x in responses["dns_ns_response_fld"].json.get("Answer", [])]

    return result(
        len(nameservers) > 1,
        f"At least two nameservers should be provided ({nameservers})",
        "ns_minimum_count",
        **kwargs,
    )
