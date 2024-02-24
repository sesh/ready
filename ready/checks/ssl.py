import errno
import socket
import ssl
from datetime import date, datetime

from ready.result import result
from ready.thttp import request

CONNECTION_TIMEOUT = 5.0


class SSLConnectionFailed(Exception):
    pass


class UnknownSSLFailure(Exception):
    pass


class LookupFailed(Exception):
    pass


def connect_with_specific_protocol(domain, protocol, ipv6=False):
    try:
        sock_type = socket.AF_INET6 if ipv6 else socket.AF_INET
        sock = socket.socket(sock_type, socket.SOCK_STREAM)

        context = ssl.SSLContext(protocol=protocol)
        ssl_sock = context.wrap_socket(sock, server_hostname=domain)
        ssl_sock.settimeout(CONNECTION_TIMEOUT)
        ssl_sock.connect((domain, 443))
        ssl_sock.close()
        return True
    except:
        return False


def get_ssl_expiry(domain, ipv6=False):
    try:
        sock_type = socket.AF_INET6 if ipv6 else socket.AF_INET
        sock = socket.socket(sock_type, socket.SOCK_STREAM)
        sock.settimeout(CONNECTION_TIMEOUT)

        context = ssl.create_default_context()
        ssl_sock = context.wrap_socket(sock, server_hostname=domain)
        ssl_sock.settimeout(CONNECTION_TIMEOUT)
        ssl_sock.connect((domain, 443))

        cert = ssl_sock.getpeercert()
        end = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]))
        ssl_sock.close()
        return end.date()
    except:
        return None


# Check: SSL certificate should be trusted
def check_ssl_certificate_should_be_trusted(responses, **kwargs):
    try:
        response = request(f'https://{kwargs["domain"]}', verify=True)
        result(
            True,
            f"SSL certificate should be trusted",
            "ssl_trusted",
            **kwargs,
        )
    except:
        result(False, f"SSL certificate should be trusted", "ssl_trusted", **kwargs)


# Check: SSL expiry should be less than one year
def check_ssl_expiry_should_be_less_than_one_year(responses, **kwargs):
    ssl_expiry = get_ssl_expiry(kwargs["domain_with_no_path"], ipv6=kwargs["is_ipv6"])
    ssl_expiry_days = (ssl_expiry - date.today()).days if ssl_expiry else None
    result(
        ssl_expiry_days and ssl_expiry_days < 366,
        f"SSL expiry should be less than one year ({ssl_expiry_days} days)",
        "ssl_expiry_max",
        **kwargs,
    )


# Check: SSL expiry should be greater than five days
def check_ssl_expiry_should_be_greater_than_five_days(responses, **kwargs):
    ssl_expiry = get_ssl_expiry(kwargs["domain_with_no_path"], ipv6=kwargs["is_ipv6"])
    ssl_expiry_days = (ssl_expiry - date.today()).days if ssl_expiry else None

    result(
        ssl_expiry_days and ssl_expiry_days > 5,
        f"SSL expiry should be greater than five days ({ssl_expiry_days} days)",
        "ssl_expiry_min",
        **kwargs,
    )


# Check: SSL connection fails when using TLS 1.1
def check_ssl_connection_fails_with_tls_1_1(responses, **kwargs):
    domain = kwargs["domain"]
    connection_successful = connect_with_specific_protocol(domain, ssl.PROTOCOL_TLSv1_1, ipv6=kwargs["is_ipv6"])

    return result(
        not connection_successful,
        f"SSL connection fails when using TLS 1.1",
        "ssl_tls_1_1",
        **kwargs,
    )


# Check: SSL connection fails when using TLS 1.0
def check_ssl_connection_fails_with_tls_1_0(responses, **kwargs):
    domain = kwargs["domain"]
    connection_successful = connect_with_specific_protocol(domain, ssl.PROTOCOL_TLSv1, ipv6=kwargs["is_ipv6"])

    return result(
        not connection_successful,
        f"SSL connection fails when using TLS 1.0",
        "ssl_tls_1_0",
        **kwargs,
    )


# Check: DNS CAA should be enabled
# https://blog.qualys.com/product-tech/2017/03/13/caa-mandated-by-cabrowser-forum
def check_dns_caa_record_should_exist(responses, **kwargs):
    records = [
        r["data"] for r in responses["dns_caa_response"].json.get("Answer", []) if "data" in r and r.get("type", 0) == 257
    ]

    if not records and "dns_caa_response_fld" in responses:
        records = [
            r["data"]
            for r in responses["dns_caa_response_fld"].json.get("Answer", [])
            if "data" in r and r.get("type", 0) == 257
        ]

    return result(
        records and all(["issue" in r or "iodef" in r for r in records]),
        f"DNS CAA should be enabled ({records})",
        "ssl_dns_caa",
        **kwargs,
    )


# Check: DNS CAA should include accounturi
def check_dns_caa_record_should_include_accounturi(responses, **kwargs):
    records = [
        r["data"] for r in responses["dns_caa_response"].json.get("Answer", []) if "data" in r and r.get("type", 0) == 257
    ]

    if not records and "dns_caa_response_fld" in responses:
        records = [
            r["data"]
            for r in responses["dns_caa_response_fld"].json.get("Answer", [])
            if "data" in r and r.get("type", 0) == 257
        ]

    # filter to just the issue records
    records = [r for r in records if "issue " in r]

    return result(
        records and all(["accounturi=" in r for r in records]),
        f"DNS CAA should include accounturi ({records})",
        "ssl_dns_caa_accounturi",
        warn_on_fail=True,
        **kwargs,
    )


# Check: DNS CAA should include validationmethods
def check_dns_caa_record_should_include_validationmethods(responses, **kwargs):
    records = [
        r["data"] for r in responses["dns_caa_response"].json.get("Answer", []) if "data" in r and r.get("type", 0) == 257
    ]

    if not records and "dns_caa_response_fld" in responses:
        records = [
            r["data"]
            for r in responses["dns_caa_response_fld"].json.get("Answer", [])
            if "data" in r and r.get("type", 0) == 257
        ]

    # filter to just the issue records
    records = [r for r in records if "issue " in r]

    return result(
        records and all(["validationmethods=" in r for r in records]),
        f"DNS CAA should include validationmethods ({records})",
        "ssl_dns_caa_validationmethods",
        warn_on_fail=True,
        **kwargs,
    )
