class ReadyResult:
    def __init__(self, passed, message, check, warn_on_fail, *, domain=None):
        self.passed = passed
        self.message = message
        self.check = check
        self.warn_on_fail = warn_on_fail
        self.domain = domain


def result(
    passed,
    message,
    check,
    *,
    warn_on_fail=False,
    colour=True,
    print_output=True,
    **kwargs,
):
    RED = "\033[0;31m" if colour else ""
    GREEN = "\033[0;32m" if colour else ""
    YELLOW = "\033[0;33m" if colour else ""
    NC = "\033[0m" if colour else ""  # No Color

    pre = f"[ {GREEN}OK{NC} ]"
    if not passed and not warn_on_fail:
        pre = f"[{RED}FAIL{NC}]"
    elif not passed:
        pre = f"[{YELLOW}WARN{NC}]"

    if print_output:
        print(f"{pre} {message}")

    return ReadyResult(passed, message, check, warn_on_fail, domain=kwargs.get("domain"))
