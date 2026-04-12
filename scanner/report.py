import json
from datetime import datetime

try:
    from rich import print
except ImportError:
    pass

class Report:
    def __init__(self, target):
        self.target = target
        self.timestamp = datetime.utcnow().isoformat()
        self.findings = []

    def add_finding(self, severity, title, endpoint, description, **kwargs):
        finding = {
            "severity": severity,
            "title": title,
            "endpoint": endpoint,
            "description": description
        }
        finding.update(kwargs)
        self.findings.append(finding)
        
    def summary(self):
        total = len(self.findings)

        severity_count = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for finding in self.findings:
            severity = finding.get("severity", "LOW")
            if severity in severity_count:
                severity_count[severity] += 1
            else:
                severity_count[severity] = 1

        return total, severity_count

    def to_json(self):
        return json.dumps({
            "target": self.target,
            "findings": self.findings
        }, indent=4)

    def save(self, filename="report.json"):
        data = {
            "target": self.target,
            "timestamp": self.timestamp,
            "findings": self.findings,
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=4)