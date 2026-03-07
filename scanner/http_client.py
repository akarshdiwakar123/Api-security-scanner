import requests

class HTTPClient:

    def __init__(self, base_url, headers=None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.headers = headers or {}
        self.session.headers.update(self.headers)

    def get(self, endpoint):
        try:
            return self.session.get(
                self.base_url + endpoint,
                timeout=5
            )
        except requests.RequestException:
            return None

    def close(self):
        self.session.close()