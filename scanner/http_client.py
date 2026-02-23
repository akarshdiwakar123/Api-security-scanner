import httpx


class HTTPClient:
    def __init__(self, base_url, headers=None):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.client = httpx.Client(timeout=10)

    def get(self, endpoint, params=None):
        url = self.base_url + endpoint
        response = self.client.get(url, headers=self.headers, params=params)
        return response

    def post(self, endpoint, data=None):
        url = self.base_url + endpoint
        response = self.client.post(url, headers=self.headers, json=data)
        return response

    def close(self):
        self.client.close()