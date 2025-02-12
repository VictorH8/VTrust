import whois
from datetime import datetime


class VTrust:
    """
    VTrust is a Python library that helps check website security.
    """

    def __init__(self):
        self.whois_data = None

    def load_whois_data(self, domain):
        self.whois_data = whois.whois(domain)

    def get_domain_info(self, domain: str) -> bool:
        if self.whois_data == None:
            self.load_whois_data(domain)

            if domain == self.whois_data.domain_name.lower():
                return True
            else:
                return False
    
    def check_domain_age(self, domain: str, min_days: int) -> bool:
        if self.whois_data == None:
            self.load_whois_data(domain)

            register_date = self.whois_data.creation_date[0] if isinstance(self.whois_data.creation_date, list) else self.whois_data.creation_date
            
            age = datetime.now() - register_date
            print(age.days)
            if age.days > min_days:
                return True
            return False

vtrust = VTrust()
print(vtrust.check_domain_age("google.com", 400))
