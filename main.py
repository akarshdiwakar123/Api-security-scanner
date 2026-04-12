import argparse
import asyncio
from scanner.tests.cors import test_cors
from datetime import datetime

try:
    from rich import print
except ImportError:
    pass

from scanner.database import save_scan

from scanner.http_client import HTTPClient
from scanner.tests.bola import test_bola
from scanner.tests.rate_limit import test_rate_limit
from scanner.tests.injection import test_injection
from scanner.report import Report
from scanner.discovery import APIDiscoverer

VERSION = "1.0"

def print_banner():
    banner = f"""
     █████╗ ██████╗ ██╗     ███████╗
    ██╔══██╗██╔══██╗██║     ██╔════╝
    ███████║██████╔╝██║     █████╗
    ██╔══██║██╔═══╝ ██║     ██╔══╝
    ██║  ██║██║     ███████╗███████╗
    ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝

        API Security Scanner v{VERSION}
        Author: Akarsh
        Inspired by OWASP API Top 10
    """
    print(banner)

async def run_tests_for_endpoint(client, ep, report):
    print(f"\n[bold magenta]=================================================[/bold magenta]")
    print(f"[bold magenta]--- Auditing Target API Endpoint: {ep} ---[/bold magenta]")
    print(f"[bold magenta]=================================================[/bold magenta]")
    
    # Run tests concurrently per endpoint
    await asyncio.gather(
        test_bola(client, ep, report),
        test_rate_limit(client, ep, report),
        test_injection(client, ep, report),
        test_cors(client, ep, report)
    )

async def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="API Security Scanner - OWASP API Top 10"
    )

    parser.add_argument("--url", required=True, help="Base API URL")
    parser.add_argument("--endpoint", help="Endpoint to test (e.g. /users/1)")
    parser.add_argument("--output", default="report.json", help="Output report file")
    parser.add_argument("--token", help="Bearer token for authentication")

    args = parser.parse_args()

    print(f"Target: {args.url}")
    print(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    print("[bold cyan]Starting API Security Scan natively accelerated via AsyncIO...[/bold cyan]")

    report = Report(target=args.url)

    headers = {}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
        print("[green]Authentication: Bearer Token Provided[/green]")
    else:
        print("[yellow]Authentication: None[/yellow]")

    client = HTTPClient(base_url=args.url, headers=headers)

    endpoints_to_test = []

    if args.endpoint:
        endpoints_to_test.append(args.endpoint)
    else:
        print("\n[yellow]⚠ No specific endpoint provided. Initiating Auto-Discovery Phase...[/yellow]")
        discoverer = APIDiscoverer(client)
        discovered = await discoverer.discover()
        
        if not discovered:
            print("[red]✖ Failed to discover any REST endpoints automatically. Please provide one manually using --endpoint.[/red]")
        else:
            # We strictly limit to the top 7 targets to prevent an exponential DDOS hang on large sites!
            endpoints_to_test = discovered[:7]
            if len(discovered) > 7:
                print(f"[yellow]⚠ Capped automated scanning to 7 endpoints specifically (out of {len(discovered)}) to prevent terminal freeze![/yellow]")

    # Run scanners logically against each endpoint. 
    # We await each endpoint block sequentially to avoid CLI output cross-contamination, 
    # but the internal modules themselves run violently concurrently.
    for ep in endpoints_to_test:
        await run_tests_for_endpoint(client, ep, report)

    await client.close()

    # Persist scan to SQLite
    target_ep = args.endpoint or "auto-discovered"
    scan_id = save_scan(args.url, target_ep, report.findings)
    print(f"[dim]Scan #{scan_id} persisted to database.[/dim]")

    report.save(args.output)

    total, severity_count = report.summary()

    print("\n======================")
    print("Scan Summary")
    print("======================")
    print(f"Total Findings: {total}")
    print(f"HIGH: {severity_count.get('HIGH', 0)}")
    print(f"MEDIUM: {severity_count.get('MEDIUM', 0)}")
    print(f"LOW: {severity_count.get('LOW', 0)}")

    print("\n[bold green]✔ Scan completed successfully.[/bold green]")
    print(f"Report organically serialized to [bold]{args.output}[/bold]")

if __name__ == "__main__":
    asyncio.run(main())