from whois_checker import WhoisChecker

class VTrust:
    """
    VTrust is a Python library that helps check website security.
    """

    def __init__(self):
        self.whois_checker = WhoisChecker()

    def check_domain_age(self, domain: str, min_days: int):
        whois_data = self.whois_checker.check_domain_age(domain, min_days)
        return whois_data

    def is_domain_active(self, domain: str):
        whois_data = self.whois_checker.is_domain_active(domain)
        return whois_data