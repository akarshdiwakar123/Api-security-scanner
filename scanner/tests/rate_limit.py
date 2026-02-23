from rich import print
import time


def test_rate_limit(client, endpoint, report, request_count=20):
    print(f"[yellow]Running Rate Limit test on {endpoint}[/yellow]")

    success_count = 0

    for _ in range(request_count):
        response = client.get(endpoint)

        if response.status_code == 200:
            success_count += 1

        time.sleep(0.05)  # small delay to simulate burst traffic

    if success_count == request_count:
        print("[bold red]⚠ No Rate Limiting Detected![/bold red]")

        report.add_finding(
            vuln_type="No Rate Limiting",
            severity="MEDIUM",
            endpoint=endpoint,
            description="API did not throttle repeated rapid requests."
        )

    else:
        print("[green]Rate limiting appears to be enforced.[/green]")