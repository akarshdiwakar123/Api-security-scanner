import argparse
from scanner.tests.cors import test_cors
from datetime import datetime
from rich import print

from scanner.http_client import HTTPClient
from scanner.tests.bola import test_bola
from scanner.tests.rate_limit import test_rate_limit
from scanner.tests.injection import test_injection
from scanner.report import Report


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


def main():
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

    print("[bold cyan]Starting API Security Scan...[/bold cyan]")

    report = Report(target=args.url)

    # ✅ Authentication handling
    headers = {}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
        print("[green]Authentication: Bearer Token Provided[/green]")
    else:
        print("[yellow]Authentication: None[/yellow]")

    client = HTTPClient(base_url=args.url, headers=headers)

    if args.endpoint:
        test_bola(client, args.endpoint, report)
        test_rate_limit(client, args.endpoint, report)
        test_injection(client, args.endpoint, report)
        test_cors(client, args.endpoint, report)
    else:
        print("[yellow]No endpoint provided. Nothing to scan.[/yellow]")

    client.close()

    report.save(args.output)

    # ✅ Scan Summary
    total, severity_count = report.summary()

    print("\n======================")
    print("Scan Summary")
    print("======================")
    print(f"Total Findings: {total}")
    print(f"HIGH: {severity_count['HIGH']}")
    print(f"MEDIUM: {severity_count['MEDIUM']}")
    print(f"LOW: {severity_count['LOW']}")

    print("\n[bold green]✔ Scan completed successfully.[/bold green]")


if __name__ == "__main__":
    main()