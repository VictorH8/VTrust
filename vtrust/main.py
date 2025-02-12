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

        if not self.whois_data or not hasattr(self.whois_data, 'creation_date'):
            print("Error: Unable to obtain domain creation data.")
            return False
        
        register_date = self.whois_data.creation_date

        if isinstance(register_date, list):
            register_date = register_date[0] if register_date else None

        if register_date is None:
            print("Error: Domain creation date not found.")
            return False

        if isinstance(register_date, str):
            try:
                register_date = datetime.strptime(register_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                print("Error: Domain creation date in invalid format.")
                return False
            

        age_days = (datetime.now() - register_date).days

        return age_days >= min_days


vtrust = VTrust()
print(vtrust.check_domain_age("google.com", 400))
