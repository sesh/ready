from ready.result import result
import re
import json
from ready import thttp


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
    records = [r["data"] for r in responses["dns_spf_response"].json.get("Answer", []) if "data" in r]

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

    for (_, record) in spf_records:
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
        records = [r["data"] for r in responses["dns_txt_response_fld"].json.get("Answer", []) if "data" in r]

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
        "email_dmarc",
        **kwargs,
    )
