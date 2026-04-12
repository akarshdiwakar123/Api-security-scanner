import re
import json
import logging
import asyncio
from urllib.parse import urljoin, urlparse

try:
    from rich import print
except ImportError:
    pass

logger = logging.getLogger(__name__)

class APIDiscoverer:
    """
    Crawler and parser engine to discover mapped API endpoints.
    Checks:
    - Swagger/OpenAPI JSON specifications
    - Heuristically crawls HTML entrypoints for routes
    - Parses JSON payloads for hypermedia HATEOAS links or nested paths
    """
    def __init__(self, client):
        self.client = client
        self.base_url = client.base_url.rstrip("/")
        self.discovered_endpoints = set()
        self.visited_urls = set()
        
        # Common OpenAPI/Swagger schema locations
        self.swagger_paths = [
            "/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs",
            "/v3/api-docs", "/docs", "/swagger/", "/api/swagger.json"
        ]

    def normalize_endpoint(self, url_or_path):
        if url_or_path.startswith("http"):
            parsed = urlparse(url_or_path)
            base_parsed = urlparse(self.base_url)
            if parsed.netloc and parsed.netloc != base_parsed.netloc:
                return None
        else:
            url_or_path = f"{self.base_url}/{url_or_path.lstrip('/')}"
            parsed = urlparse(url_or_path)

        path = parsed.path
        if not path.startswith("/"):
            path = "/" + path
            
        final_ep = path + ("?" + parsed.query if parsed.query else "")
        return final_ep

    async def extract_from_swagger(self):
        print("[cyan]  → Hunting for OpenAPI/Swagger documentation catalogs...[/cyan]")
        for path in self.swagger_paths:
            try:
                res = await self.client.session.get(path, timeout=5.0) # httpx client maps to base automatically
                content_type = res.headers.get("Content-Type", "")
                
                if res.status_code == 200 and "json" in content_type.lower():
                    data = res.json()
                    if "paths" in data and isinstance(data["paths"], dict):
                        print(f"[green]✔ Found Swagger/OpenAPI schema at {path}[/green]")
                        for api_path in data["paths"].keys():
                            ep = self.normalize_endpoint(api_path)
                            if ep:
                                self.discovered_endpoints.add(ep)
                        return True
            except Exception:
                continue
        return False

    async def crawl_and_extract(self, path="/", depth=2):
        if depth == 0 or path in self.visited_urls:
            return
            
        self.visited_urls.add(path)
        
        try:
            res = await self.client.session.get(path, timeout=5.0)
        except Exception:
            return
            
        if not res or res.status_code >= 400:
            return
            
        content_type = res.headers.get("Content-Type", "")
        
        tasks = []
        if "json" in content_type.lower():
            try:
                data = res.json()
                data_str = json.dumps(data)
                
                paths = re.findall(r'"(/[a-zA-Z0-9_/?&=-]+)"', data_str)
                for p in paths:
                    ep = self.normalize_endpoint(p)
                    if ep and ep not in self.visited_urls:
                        self.discovered_endpoints.add(ep)
                        tasks.append(self.crawl_and_extract(ep, depth - 1))
            except Exception:
                pass
        else:
            # HTML text format
            paths = re.findall(r'(?:href|src|url|action)=["\']?(/[a-zA-Z0-9_/?&=-]+)["\']?', res.text)
            for p in paths:
                ep = self.normalize_endpoint(p)
                if ep and ep not in self.visited_urls:
                    self.discovered_endpoints.add(ep)
                    tasks.append(self.crawl_and_extract(ep, depth - 1))
                    
            urls = re.findall(r'(https?://[^\s"\']+)', res.text)
            for u in urls:
                ep = self.normalize_endpoint(u)
                if ep and ep not in self.visited_urls:
                    self.discovered_endpoints.add(ep)
                    tasks.append(self.crawl_and_extract(ep, depth - 1))

        if tasks:
            await asyncio.gather(*tasks)

    async def discover(self):
        print(f"\n[bold cyan]Starting Intelligent API Endpoint Discovery on {self.base_url}[/bold cyan]")
        
        await self.extract_from_swagger()
        
        print("[cyan]  → Initiating deep-crawl of base infrastructure...[/cyan]")
        
        # We can trigger initial seeds concurrently
        await asyncio.gather(
            self.crawl_and_extract("/"),
            self.crawl_and_extract("/api"),
            self.crawl_and_extract("/api/v1"),
            self.crawl_and_extract("/graphql")
        )

        endpoints = [ep for ep in self.discovered_endpoints if ep != "/"]
        endpoints = sorted(list(endpoints))
        
        print(f"[bold green]✔ Discovery complete. Isolated {len(endpoints)} endpoints.[/bold green]")
        
        for ep in endpoints[:15]:
            print(f"    - {ep}")
            
        if len(endpoints) > 15:
            print(f"    ... and {len(endpoints) - 15} more.")
            
        return endpoints
