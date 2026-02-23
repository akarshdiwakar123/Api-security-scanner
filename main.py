import argparse
VERSION = "1.0"
def print_banner():
    banner = r"""
     █████╗ ██████╗ ██╗     ███████╗
    ██╔══██╗██╔══██╗██║     ██╔════╝
    ███████║██████╔╝██║     █████╗
    ██╔══██║██╔═══╝ ██║     ██╔══╝
    ██║  ██║██║     ███████╗███████╗
    ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝

        API Security Scanner v1.0
        Author: Akarsh
        Inspired by OWASP API Top 10
    """
    print(banner)
from scanner.tests.injection import test_injection
from rich import print
from scanner.http_client import HTTPClient
from scanner.auth import AuthHandler
from scanner.tests.bola import test_bola
from scanner.tests.rate_limit import test_rate_limit
from scanner.report import Report


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="API Security Scanner - OWASP API Top 10"
    )

    parser.add_argument("--url", required=True, help="Base API URL")
    parser.add_argument("--token", help="Bearer JWT Token (optional)")
    parser.add_argument("--endpoint", help="Endpoint to test (e.g. /users/1)")
    parser.add_argument("--output", help="Output report file name", default="report.json")

    args = parser.parse_args()
    from datetime import datetime

    print(f"Target: {args.url}")
    print(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    

    print("[bold cyan]Starting API Security Scan...[/bold cyan]")

    report = Report(target=args.url)

    auth = AuthHandler(args.token)
    headers = auth.get_auth_header()

    if args.token:
        auth.decode_jwt()

    client = HTTPClient(base_url=args.url, headers=headers)

    if args.endpoint:
        test_bola(client, args.endpoint, report)
        test_rate_limit(client, args.endpoint, report)
        test_injection(client, args.endpoint, report)
    else:
        print("[yellow]No endpoint provided. Nothing to scan.[/yellow]")

    client.close()

   report.save(args.output)

# Print summary
total, severity_count = report.summary()

print("\n======================")
print("Scan Summary")
print("======================")
print(f"Total Findings: {total}")
print(f"HIGH: {severity_count['HIGH']}")
print(f"MEDIUM: {severity_count['MEDIUM']}")
print(f"LOW: {severity_count['LOW']}")

print("\nScan completed.")
if __name__ == "__main__":
    main()