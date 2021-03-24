from ready.result import result


# Check: SPF TXT record should exist
def check_spf_record_should_exist(responses, **kwargs):
    records = [r["data"] for r in responses["dns_txt_response"].json.get("Answer", []) if r["data"].startswith("v=spf")]

    return result(
        len(records) > 0,
        f"SPF TXT record should exist ({records})",
        "email_spf",
        **kwargs,
    )


# Check: SPF TXT record should contain "-all"
def check_spf_txt_record_should_disallow_all(responses, **kwargs):
    records = [r["data"] for r in responses["dns_txt_response"].json.get("Answer", []) if r["data"].startswith("v=spf")]

    return result(
        records and all(["-all" in r for r in records]),
        f'SPF TXT record should contain "-all" ({records})',
        "email_spf_disallow_all",
        **kwargs,
    )


# Check: SPF DNS record is depreciated and should not exist
def check_spf_dns_record_does_not_exist(responses, **kwargs):
    records = [r["data"] for r in responses["dns_spf_response"].json.get("Answer", []) if "data" in r]

    return result(
        len(records) == 0,
        f"SPF DNS record is depreciated and should not exist ({records})",
        "email_spf_dns",
        **kwargs,
    )


# Check: DMARC record should exist
def check_dmarc_record_should_exist(responses, **kwargs):
    records = [r["data"] for r in responses["dns_dmarc_response"].json.get("Answer", []) if "data" in r]
    return result(
        records and all([r.startswith("v=DMARC1") for r in records]),
        f"DMARC record should exist ({records})",
        "email_dmarc",
        **kwargs,
    )
