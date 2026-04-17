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

    def generate_pdf(self, endpoint="/"):
        from io import BytesIO
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer)
        styles = getSampleStyleSheet()
        elements = [
            Paragraph("<b>API Security Scan Report</b>", styles["Title"]),
            Spacer(1, 0.5 * inch),
            Paragraph(f"Target: {self.target}", styles["Normal"]),
            Paragraph(f"Endpoint: {endpoint}", styles["Normal"]),
            Paragraph(f"Date: {self.timestamp}", styles["Normal"]),
            Spacer(1, 0.5 * inch),
        ]

        if self.findings:
            for f in self.findings:
                elements.append(Paragraph(f"<b>{f.get('title', 'N/A')} — {f.get('severity', '')}</b>", styles["Normal"]))
                elements.append(Paragraph(f"Endpoint: {f.get('endpoint', '')}", styles["Normal"]))
                elements.append(Paragraph(f"Description: {f.get('description', '')}", styles["Normal"]))
                elements.append(Spacer(1, 0.3 * inch))
        else:
            elements.append(Paragraph("No vulnerabilities detected.", styles["Normal"]))

        doc.build(elements)
        buffer.seek(0)
        return buffer