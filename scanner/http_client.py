import requests


class HTTPClient:
    def __init__(self, base_url, headers=None):
        self.base_url = base_url
        self.session = requests.Session()

        if headers:
            self.session.headers.update(headers)

    def get(self, endpoint):
        try:
            response = self.session.get(f"{self.base_url}{endpoint}")
            return response
        except requests.RequestException:
            return None

    def close(self):
        self.session.close()