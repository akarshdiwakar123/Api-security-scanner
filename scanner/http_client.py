import httpx
import logging

logger = logging.getLogger(__name__)

class HTTPClient:
    def __init__(self, base_url, headers=None):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        # We explicitly disable redirects. Security tools need to analyze the direct HTTP response.
        self.session = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            follow_redirects=False,
            verify=False # Often needed against self-signed local test targets
        )

    async def get(self, endpoint, timeout=10.0, **kwargs):
        try:
            return await self.session.get(endpoint, timeout=timeout, **kwargs)
        except httpx.RequestError as e:
            logger.debug(f"HTTP GET Request failed: {e}")
            return None

    async def options(self, endpoint, timeout=10.0, **kwargs):
        try:
            return await self.session.options(endpoint, timeout=timeout, **kwargs)
        except httpx.RequestError as e:
            logger.debug(f"HTTP OPTIONS Request failed: {e}")
            return None

    async def close(self):
        await self.session.aclose()