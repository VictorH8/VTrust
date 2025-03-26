from .check_security_headers import SecurityHeadersChecker
from .whois_checker import WhoisChecker
from .check_ssl import CheckSsl


class VTrust:
    """
    VTrust is a Python library that helps check website security.
    """

    def __init__(self):
        self.whois_checker = WhoisChecker()
        self.headers_checker = SecurityHeadersChecker()

    def check_domain_age(self, domain: str, min_days: int):
        return self.whois_checker.check_domain_age(domain, min_days)

    def is_domain_active(self, domain: str):
        return self.whois_checker.is_domain_active(domain)

    def is_cache_control_secure(self, domain: str):
        return self.headers_checker.is_cache_control_secure(domain)

    def check_security_headers(self, domain: str):
        return self.headers_checker.check_security_headers(domain)

    def check_ssl(self, domain: str):
        return CheckSsl.check_ssl(domain)
