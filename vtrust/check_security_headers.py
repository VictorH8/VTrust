import httpx


class SecurityHeadersChecker:
    def __init__(self):
        self.headers_data = None

    def load_headers(self, domain: str):
        self.headers_data = httpx.get(domain)

    def is_cache_control_secure(self, domain: str):
        if self.headers_data == None:
            self.load_headers(domain)
        
        headers = self.headers_data.headers

        if "cache-control" not in headers:
            return False

        cache_control = headers["cache-control"].lower()

        if "max-age=" not in cache_control:
            return False
        
        try:
            max_age = int(cache_control.split("max-age=", 1)[1])
            return max_age >= 31536000
        except ValueError:
            return False
        