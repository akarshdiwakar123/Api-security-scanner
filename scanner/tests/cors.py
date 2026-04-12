import logging
import asyncio
from urllib.parse import urlparse

try:
    from rich import print
except ImportError:
    pass

logger = logging.getLogger(__name__)

async def test_cors(client, endpoint, report):
    print(f"\n[bold cyan]Running CORS Misconfiguration test on {endpoint}[/bold cyan]")
    
    try:
        parsed = urlparse(client.base_url)
        target_domain = parsed.hostname or parsed.netloc or "target.com"
    except Exception:
        target_domain = "target.com"

    test_origins = [
        "https://evil.com",
        "null",
        f"https://{target_domain}.evil.com"
    ]

    findings = set()
    
    async def invoke_cors(origin, method):
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "GET"
        }
        try:
            if method == 'OPTIONS':
                response = await client.options(endpoint, headers=headers, timeout=10.0)
            else:
                response = await client.get(endpoint, headers=headers, timeout=10.0)
            return (origin, method, response)
        except Exception as e:
            logger.debug(f"CORS {method} request failed: {e}")
            return (origin, method, None)

    tasks = []
    for origin in test_origins:
        for method in ['OPTIONS', 'GET']:
            tasks.append(invoke_cors(origin, method))
            
    results = await asyncio.gather(*tasks)

    for origin, method, response in results:
        if not response or not hasattr(response, "headers"):
            continue

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if not acao:
            continue

        vulnerable = False
        severity = "LOW"
        title = "CORS Misconfiguration"
        description = ""

        if acao == origin:
            vulnerable = True
            if acac:
                severity = "HIGH"
                description = f"Reflected arbitrary Origin ('{origin}') with Allow-Credentials=True via {method} request. Highly exploitable."
            else:
                severity = "MEDIUM"
                description = f"Reflected arbitrary Origin ('{origin}') via {method} request without credentials."

        elif origin == "null" and acao == "null":
            vulnerable = True
            if acac:
                severity = "HIGH"
                description = f"Origin 'null' is allowed with Allow-Credentials=True via {method} request. Easily bypassable."
            else:
                severity = "MEDIUM"
                description = f"Origin 'null' is allowed via {method} request."

        elif acao == "*":
            vulnerable = True
            if acac:
                severity = "HIGH"
                description = f"Wildcard (*) Origin combined with Allow-Credentials via {method} request. Invalid spec but implies severe misconfiguration."
            else:
                severity = "LOW"
                description = f"Wildcard (*) Origin allowed via {method} request. Typical for public APIs but verify necessity."

        if vulnerable:
            finding_key = f"{severity}-{description}"
            if finding_key not in findings:
                findings.add(finding_key)
                print(f"[yellow]⚠ Potential CORS Misconfiguration detected ({severity}): {method} / {origin}[/yellow]")
                
                try:
                    report.add_finding(
                        severity=severity,
                        title=title,
                        endpoint=endpoint,
                        description=description
                    )
                except TypeError:
                    report.add_finding(
                        severity,
                        title,
                        endpoint,
                        description
                    )