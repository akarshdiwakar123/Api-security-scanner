import argparse
import asyncio
from datetime import datetime

try:
    from rich import print
except ImportError:
    pass

from scanner.core.engine import ScanConfig, run_scan

VERSION = "2.0"


def print_banner():
    banner = f"""
     █████╗ ██████╗ ██╗     ███████╗
    ██╔══██╗██╔══██╗██║     ██╔════╝
    ███████║██████╔╝██║     █████╗
    ██╔══██║██╔═══╝ ██║     ██╔══╝
    ██║  ██║██║     ███████╗███████╗
    ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝

        API Security Scanner v{VERSION}
        Author: Akarsh | OWASP API Top 10
    """
    print(banner)


async def main():
    print_banner()

    parser = argparse.ArgumentParser(description="API Security Scanner — OWASP API Top 10")
    parser.add_argument("--url",      required=True, help="Base API URL")
    parser.add_argument("--endpoint", required=True, help="Endpoint to test (e.g. /users/1)")
    parser.add_argument("--output",   default="report.json", help="Output JSON report file")
    parser.add_argument("--token",    help="Bearer token for authentication")
    parser.add_argument("--no-db",    action="store_true", help="Skip saving to the database")
    args = parser.parse_args()

    print(f"Target:  {args.url}{args.endpoint}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print("[bold cyan]Starting asynchronous security scan...[/bold cyan]")

    if args.token:
        print("[green]Auth: Bearer Token Provided[/green]")
    else:
        print("[yellow]Auth: None[/yellow]")

    config = ScanConfig(
        url=args.url,
        endpoint=args.endpoint,
        token=args.token,
        persist=not args.no_db,
    )

    result = await run_scan(config)

    # Save JSON report to disk
    import json
    report_data = {
        "scan_id":  result.scan_id,
        "target":   result.target,
        "endpoint": result.endpoint,
        "total":    result.total,
        "high":     result.high,
        "medium":   result.medium,
        "low":      result.low,
        "findings": result.findings,
    }
    with open(args.output, "w") as f:
        json.dump(report_data, f, indent=4)

    print("\n======================")
    print("Scan Summary")
    print("======================")
    print(f"Total Findings : {result.total}")
    print(f"HIGH           : {result.high}")
    print(f"MEDIUM         : {result.medium}")
    print(f"LOW            : {result.low}")

    if result.scan_id:
        print(f"\n[dim]Scan #{result.scan_id} persisted to database.[/dim]")

    print(f"\n[bold green]✔ Scan completed. Report saved to {args.output}[/bold green]")


if __name__ == "__main__":
    asyncio.run(main())