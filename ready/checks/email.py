import json
import re

from ready import thttp
from ready.result import result


# Check: SPF TXT record should exist
def check_spf_record_should_exist(responses, **kwargs):
    records = [r["data"] for r in responses["dns_txt_response"].json.get("Answer", []) if r["data"].startswith("v=spf")]

    if not records and "dns_txt_response_fld" in responses:
        records = [r["data"] for r in responses["dns_txt_response_fld"].json.get("Answer", []) if r["data"].startswith("v=spf")]

    return result(
        len(records) > 0,
        f"SPF TXT record should exist ({records})",
        "email_spf",
        **kwargs,
    )


# Check: SPF TXT record should contain "-all"
def check_spf_txt_record_should_disallow_all(responses, **kwargs):
    records = [r["data"] for r in responses["dns_txt_response"].json.get("Answer", []) if r["data"].startswith("v=spf")]

    if not records and "dns_txt_response_fld" in responses:
        records = [r["data"] for r in responses["dns_txt_response_fld"].json.get("Answer", []) if r["data"].startswith("v=spf")]

    return result(
        records and all(["-all" in r for r in records]),
        f'SPF TXT record should contain "-all" ({records})',
        "email_spf_disallow_all",
        **kwargs,
    )


# Check: SPF DNS record is depreciated and should not exist
def check_spf_dns_record_does_not_exist(responses, **kwargs):
    records = [r["data"] for r in responses["dns_spf_response"].json.get("Answer", []) if "data" in r and r["type"] == 99]

    if "dns_spf_response_fld" in responses:
        records.extend([r["data"] for r in responses["dns_spf_response_fld"].json.get("Answer", []) if "data" in r])

    return result(
        len(records) == 0,
        f"SPF DNS record is depreciated and should not exist ({records})",
        "email_spf_dns",
        **kwargs,
    )


def _spf_for_domain(domain, depth=0, lookups=[]):
    if domain in lookups:
        return []

    response = thttp.request(f"https://dns.google/resolve?name={domain}&type=TXT")
    lookups.append(domain)

    j = json.loads(response.content)

    spf_records = [(domain, x["data"]) for x in j.get("Answer", []) if x["data"].startswith("v=spf")]

    results = [x for x in spf_records]

    for _, record in spf_records:
        depth += 1
        if depth > 13:
            return results

        matches = re.findall("include\:([^\s]+)", record)

        for d in matches:
            results.extend(_spf_for_domain(d, depth, lookups))

        matches = re.findall("redirect\=([^\s]+)", record)

        for d in matches:
            results.extend(_spf_for_domain(d, depth, lookups))

    return results


# Check: SPF includes use less than 10 DNS requests
def check_spf_uses_less_than_10_requests(responses, **kwargs):
    records = [r["data"] for r in responses["dns_txt_response"].json.get("Answer", []) if r["data"].startswith("v=spf")]

    if not records and "dns_txt_response_fld" in responses:
        records = [
            r["data"]
            for r in responses["dns_txt_response_fld"].json.get("Answer", [])
            if "data" in r and r["data"].startswith("v=spf")
        ]

    additional_lookups = []
    for record in records:
        matches = re.findall("include\:([^\s]+)", record)

        for d in matches:
            additional_lookups.extend(_spf_for_domain(d))

        matches = re.findall("redirect\=([^\s]+)", record)

        for d in matches:
            additional_lookups.extend(_spf_for_domain(d))

    return result(
        len(additional_lookups) <= 10,
        f"SPF includes use less than 10 DNS requests ({len(additional_lookups)})",
        "email_spf_recursion",
        **kwargs,
    )


# Check: DMARC record should exist
def check_dmarc_record_should_exist(responses, **kwargs):
    records = [r["data"] for r in responses["dns_dmarc_response"].json.get("Answer", []) if "data" in r]

    if not records and "dns_dmarc_response_fld" in responses:
        records = [r["data"] for r in responses["dns_dmarc_response_fld"].json.get("Answer", []) if "data" in r]

    return result(
        records and all([r.startswith("v=DMARC1") for r in records]),
        f"DMARC record should exist ({records})",
        "email_dmarc_exists",
        **kwargs,
    )


# Check: DMARC record should contain p=reject
def check_dmarc_record_should_reject_failures(responses, **kwargs):
    records = [r["data"] for r in responses["dns_dmarc_response"].json.get("Answer", []) if "data" in r]

    if not records and "dns_dmarc_response_fld" in responses:
        records = [r["data"] for r in responses["dns_dmarc_response_fld"].json.get("Answer", []) if "data" in r]

    failing = True

    for r in records:
        if "p=reject" in [x.strip().lower() for x in r.split(";")]:
            failing = False

    return result(
        not failing,
        f"DMARC record should contain p=reject ({records})",
        "email_dmarc_none",
        **kwargs,
    )


# Check: SPF should be "v=spf1 -all" if there are no MX records or MX record is "."
def check_spf_dash_all(responses, **kwargs):
    # return none if there is an mx record
    mx_records = []
    if responses["dns_mx_response"] and "Answer" in responses["dns_mx_response"].json:
        mx_records.extend(responses["dns_mx_response"].json["Answer"])

    if "dns_mx_response_fld" in responses and "Answer" in responses["dns_mx_response_fld"].json:
        mx_records.extend(responses["dns_mx_response_fld"].json["Answer"])

    mx_record_data = [r["data"] for r in mx_records]

    if len(mx_record_data) == 0 or all([r == "0 ." for r in mx_record_data]):
        spf_records = [r["data"] for r in responses["dns_txt_response"].json.get("Answer", []) if r["data"].startswith("v=spf")]

        if spf_records:
            spf_record = spf_records[0]
        else:
            spf_record = ""

        return result(
            spf_record.lower().strip() == "v=spf1 -all",
            f"SPF should be 'v=spf1 -all' if there are no MX records or MX record is '.' ({spf_record})",
            "email_spf_disallow_all_with_empty_mx",
            **kwargs,
        )
    else:
        return result(
            True,
            f"SPF should be 'v=spf1 -all' if there are no MX records or MX record is '.' (MX records exist: {mx_record_data})",
            "email_spf_disallow_all_with_empty_mx",
            **kwargs,
        )
