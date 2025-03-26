from datetime import datetime

import whois


class WhoisChecker:
    def __init__(self):
        self.whois_data = None

    def load_whois_data(self, domain):
        self.whois_data = whois.whois(domain)
    
    def check_domain_age(self, domain: str, min_days: int) -> bool:
        """
        Checks if the domain is older than the specified minimum age.
            :param domain: The domain name to check.
            :param min_days: The minimum age in days that the domain should have.
            :return: True if the domain is older than the specified age, False otherwise.
        """
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
    

    def is_domain_active(self, domain: str):
        """
        Checks if the domain is active based on its expiration date.
            :param domain: The domain name to check.
            :return: True if the domain is active, False if expired or no expiration date.
        """
        if self.whois_data == None:
            self.load_whois_data(domain)

        if self.whois_data.expiration_date:

            expiration_date = self.whois_data.expiration_date[0]
            expiration_date = expiration_date.date()

            if expiration_date > datetime.now().date():
                return True
            else:
                return False
        else:
            return False