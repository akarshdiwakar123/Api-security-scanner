import time
import logging
import asyncio

try:
    from rich import print
except ImportError:
    pass

logger = logging.getLogger(__name__)

async def test_rate_limit(client, endpoint, report):
    """
    Test an endpoint for Rate Limiting / Brute Force protection mechanisms.
    - Sends a concurrent robust burst of 50 asynchronous requests
    """
    print(f"\n[bold cyan]Running Rate Limiting & Throttling burst test on {endpoint}[/bold cyan]")
    
    burst_count = 50
    results = []
    
    async def make_request(req_id):
        start = time.time()
        try:
            headers = {"Cache-Control": "no-cache", "X-Scanner-Req-Id": str(req_id)}
            res = await client.get(endpoint, headers=headers, timeout=5.0)
            
            return {
                "id": req_id,
                "status": getattr(res, "status_code", None),
                "time": time.time() - start,
                "success": res is not None,
                "error": None if res else "Response Null"
            }
        except Exception as e:
            return {
                "id": req_id,
                "status": None,
                "time": time.time() - start,
                "success": False,
                "error": str(e)
            }

    print(f"  → Deploying {burst_count} highly concurrent asynchronous requests via HTTPX...")
    
    # Natively trigger IO bounds asynchronously
    tasks = [make_request(i) for i in range(burst_count)]
    results = await asyncio.gather(*tasks)

    success_requests = [r for r in results if r["success"]]
    if not success_requests:
        logger.error(f"Rate limiting test failed entirely (perhaps bad network): {results[0]['error']}")
        return

    status_codes = [r["status"] for r in success_requests]
    
    if 429 in status_codes:
        print("[green]✔ Protective HTTP 429 (Too Many Requests) detected. Endpoint is safely rate-limited.[/green]")
        return
        
    for w_code in [403, 401, 503]:
        count = status_codes.count(w_code)
        if count > 0 and count < burst_count:
            print(f"[green]✔ Aggressive WAF blocking sequence detected (triggering HTTP {w_code}s).[/green]")
            return

    failed_requests = [r for r in results if not r["success"]]
    timeout_failures = [r for r in failed_requests if "timeout" in (r["error"] or "").lower()]
    connection_drops = len(failed_requests)
    
    if connection_drops > int(burst_count * 0.2): 
        print("[yellow]✔ Soft Network-layer protective blocking detected (TCP drops/Timeouts).[/yellow]")
        return

    times = [r["time"] for r in success_requests]
    avg_time = sum(times) / len(times) if times else 0
    max_time = max(times) if times else 0
    min_time = min(times) if times else 0

    severity = "HIGH"
    confidence = "HIGH"
    description = (
        f"Missing Rate Limiting mechanism. "
        f"Server successfully handled an asynchronous burst of {burst_count} rapid requests "
        f"without triggering 429 bans or WAF intervention. "
        f"Metrics (RTT) - Min: {min_time:.3f}s / Max: {max_time:.3f}s / Avg: {avg_time:.3f}s. "
        f"Confidence is {confidence}."
    )

    if max_time > (3 * min_time) and max_time > 1.0:
        severity = "MEDIUM"
        confidence = "MEDIUM"
        description = (
            f"Possible API Soft-Throttling or resource exhaustion. "
            f"No HTTP 429 received over {burst_count} burst requests, but extreme degradation in "
            f"response timing detected (Max: {max_time:.3f}s vs Min: {min_time:.3f}s). "
            f"Confidence: {confidence}"
        )

    print(f"[red]⚠ Vulnerability: Missing Rate Limiting ({severity})[/red]")

    try:
        report.add_finding(
            severity=severity,
            title="Missing Rate Limiting",
            endpoint=endpoint,
            description=description
        )
    except TypeError:
        report.add_finding(
            severity,
            "Missing Rate Limiting",
            endpoint,
            description
        )