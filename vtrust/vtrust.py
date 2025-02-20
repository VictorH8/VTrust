from whois_checker import WhoisChecker
from check_security_headers import SecurityHeadersChecker


class VTrust:

    """
    VTrust is a Python library that helps check website security.
    """

    def __init__(self):
        self.whois_checker = WhoisChecker()
        self.HeadersChecker = SecurityHeadersChecker()

    def check_domain_age(self, domain: str, min_days: int):
        domain_age = self.whois_checker.check_domain_age(domain, min_days)
        return domain_age

    def is_domain_active(self, domain: str):
        domain_active = self.whois_checker.is_domain_active(domain)
        return domain_active
    
    def is_cache_control_secure(self, domain: str):
        is_cache_control_secure = self.HeadersChecker.is_cache_control_secure(domain)
        return is_cache_control_secure