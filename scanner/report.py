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
        
    def summary(self):
        total = len(self.findings)

        severity_count = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for finding in self.findings:
            severity = finding["severity"]
            if severity in severity_count:
                severity_count[severity] += 1

        return total, severity_count

    def save(self, filename="report.json"):
        data = {
            "target": self.target,
            "timestamp": self.timestamp,
            "findings": self.findings,
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=4)

        