from rich import print
import re


def test_bola(client, endpoint, report):
    print(f"[yellow]Running BOLA test on {endpoint}[/yellow]")

    match = re.search(r"(\d+)", endpoint)

    if not match:
        print("[red]No numeric ID found in endpoint. Skipping BOLA test.[/red]")
        return

    original_id = match.group(1)
    new_id = str(int(original_id) + 1)

    modified_endpoint = endpoint.replace(original_id, new_id)

    response = client.get(modified_endpoint)

    if response.status_code == 200:
        print("[bold red]⚠ Potential BOLA Vulnerability Detected![/bold red]")

        report.add_finding(
            vuln_type="BOLA",
            severity="HIGH",
            endpoint=modified_endpoint,
            description="Unauthorized object access possible."
        )

    else:
        print("[green]BOLA test passed.[/green]")