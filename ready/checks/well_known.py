from ready.result import result


# Check: Robots.txt exists and is a text file
def check_robots_txt_exists(responses, **kwargs):
    robots_response = responses["robots_txt_response"]

    return result(
        robots_response and robots_response.status == 200 and "text/plain" in robots_response.headers.get("content-type", ""),
        "Robots.txt exists and is a text file",
        "wellknown_robots",
        **kwargs
    )


# Check: Security.txt exists and is a text file that contains required attributes
def check_security_txt_exists(responses, **kwargs):
    security_txt_response = responses["security_txt_response"]

    return result(
        security_txt_response
        and security_txt_response.status == 200
        and "text/plain" in security_txt_response.headers.get("content-type", "")
        and b"Contact:" in security_txt_response.content
        and b"Expires:" in security_txt_response.content,
        "Security.txt exists and is a text file that contains required attributes",
        "wellknown_security",
        **kwargs
    )


# Check: Favicon is served at /favicon.ico
def check_favicon_is_served(responses, **kwargs):
    favicon_response = responses["favicon_response"]
    return result(
        favicon_response.status == 200
        and favicon_response.headers.get("content-type", "") in ["image/x-icon", "image/vnd.microsoft.icon"],
        "Favicon is served at /favicon.ico",
        "wellknown_favicon",
        **kwargs
    )
