import argparse
from rich import print
from scanner.http_client import HTTPClient
from scanner.auth import AuthHandler
from scanner.tests.bola import test_bola


def main():
    parser = argparse.ArgumentParser(
        description="API Security Scanner - OWASP API Top 10"
    )

    parser.add_argument("--url", required=True, help="Base API URL")
    parser.add_argument("--token", help="Bearer JWT Token (optional)")
    parser.add_argument("--endpoint", help="Endpoint to test (e.g. /users/1)")

    args = parser.parse_args()

    print("[bold cyan]Starting API Security Scan...[/bold cyan]")

    # Setup authentication
    auth = AuthHandler(args.token)
    headers = auth.get_auth_header()

    if args.token:
        auth.decode_jwt()

    # Setup HTTP client
    client = HTTPClient(base_url=args.url, headers=headers)

    # Run BOLA test if endpoint provided
    if args.endpoint:
        test_bola(client, args.endpoint)
    else:
        print("[yellow]No endpoint provided. Nothing to scan.[/yellow]")

    client.close()

    print("[bold green]Scan completed.[/bold green]")


if __name__ == "__main__":
    main()