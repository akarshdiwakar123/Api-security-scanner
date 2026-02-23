import json
from datetime import datetime
from rich import print


class Report:
    def __init__(self, target):
        self.target = target
        self.timestamp = datetime.utcnow().isoformat()
        self.findings = []

    def add_finding(self, vuln_type, severity, endpoint, description):
        finding = {
            "type": vuln_type,
            "severity": severity,
            "endpoint": endpoint,
            "description": description,
        }
        self.findings.append(finding)

    def save(self, filename="report.json"):
        data = {
            "target": self.target,
            "timestamp": self.timestamp,
            "findings": self.findings,
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=4)

        print(f"[bold green]Report saved to {filename}[/bold green]")