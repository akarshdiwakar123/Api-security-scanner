import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from io import BytesIO

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

from scanner.http_client import HTTPClient
from scanner.tests.bola import test_bola
from scanner.tests.rate_limit import test_rate_limit
from scanner.tests.injection import test_injection
from scanner.tests.cors import test_cors
from scanner.report import Report


# =========================
# PAGE CONFIG
# =========================
st.set_page_config(page_title="CYBERPUNK API SCANNER", layout="wide")

# =========================
# SESSION STORAGE
# =========================
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

# =========================
# PDF GENERATOR
# =========================
def generate_pdf(report, url, endpoint):

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)
    elements = []

    styles = getSampleStyleSheet()

    elements.append(Paragraph("<b>API Security Scan Report</b>", styles["Title"]))
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph(f"Target: {url}", styles["Normal"]))
    elements.append(Paragraph(f"Endpoint: {endpoint}", styles["Normal"]))
    elements.append(Spacer(1, 0.5 * inch))

    if report.findings:
        for finding in report.findings:
            elements.append(Paragraph(
                f"<b>{finding['type']} - {finding['severity']}</b>",
                styles["Normal"]
            ))
            elements.append(Paragraph(
                f"Endpoint: {finding['endpoint']}",
                styles["Normal"]
            ))
            elements.append(Paragraph(
                f"Description: {finding['description']}",
                styles["Normal"]
            ))
            elements.append(Spacer(1, 0.3 * inch))
    else:
        elements.append(Paragraph("No vulnerabilities detected.", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer


# =========================
# CYBERPUNK CSS
# =========================
st.markdown("""
<style>
.stApp { background-color: #0d0d0d; color: #00ffcc; }
h1 { color: #ff00ff; text-shadow: 0 0 15px #ff00ff; }
input { background-color: #111 !important; color: #00ffcc !important; border: 1px solid #00ffcc !important; }
.stButton>button { background-color: black; color: #00ffcc; border: 2px solid #00ffcc; box-shadow: 0 0 10px #00ffcc; }
.stButton>button:hover { background-color: #00ffcc; color: black; box-shadow: 0 0 20px #00ffcc; }
[data-testid="stMetric"] { background-color: #111; border: 1px solid #ff00ff; padding: 15px; border-radius: 10px; box-shadow: 0 0 15px #ff00ff; }
section[data-testid="stSidebar"] { background-color: #111; border-right: 1px solid #00ffcc; }
</style>
""", unsafe_allow_html=True)

# =========================
# SIDEBAR
# =========================
st.sidebar.title("⚡ CYBER SECURITY TERMINAL")
st.sidebar.markdown("System Status: 🟢 ONLINE")
st.sidebar.markdown("---")
st.sidebar.info("OWASP API Top 10 Scanner")

# =========================
# MAIN UI
# =========================
st.title("🔐 CYBERPUNK API SECURITY SCANNER")

col1, col2 = st.columns(2)

with col1:
    url = st.text_input("Target Base URL")

with col2:
    endpoint = st.text_input("Endpoint (e.g. /users/1)")

token = st.text_input("Bearer Token (Optional)", type="password")

run_scan = st.button("🚀 INITIATE SCAN")

# =========================
# SCAN LOGIC
# =========================
if run_scan:

    if not url or not endpoint:
        st.error("TARGET PARAMETERS MISSING.")
    else:
        with st.spinner("Scanning target system..."):

            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"

            client = HTTPClient(base_url=url, headers=headers)
            report = Report(target=url)

            test_bola(client, endpoint, report)
            test_rate_limit(client, endpoint, report)
            test_injection(client, endpoint, report)
            test_cors(client, endpoint, report)

            client.close()

        st.success("SCAN COMPLETE ⚡")

        total, severity_count = report.summary()

        # Save scan history
        scan_record = {
            "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Target": url,
            "Endpoint": endpoint,
            "Total": total,
            "HIGH": severity_count["HIGH"],
            "MEDIUM": severity_count["MEDIUM"],
            "LOW": severity_count["LOW"]
        }

        st.session_state.scan_history.append(scan_record)

        # =========================
        # METRICS
        # =========================
        st.subheader("⚡ THREAT SUMMARY")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("TOTAL", total)
        col2.metric("HIGH 🔴", severity_count["HIGH"])
        col3.metric("MEDIUM 🟠", severity_count["MEDIUM"])
        col4.metric("LOW 🟢", severity_count["LOW"])

        # =========================
        # PIE CHART
        # =========================
        if total > 0:
            st.subheader("⚡ THREAT DISTRIBUTION")

            labels = list(severity_count.keys())
            values = list(severity_count.values())

            fig, ax = plt.subplots()
            ax.pie(values, labels=labels, autopct='%1.1f%%')
            st.pyplot(fig)

        # =========================
        # FINDINGS
        # =========================
        st.subheader("⚡ DETECTED VULNERABILITIES")

        if report.findings:
            for finding in report.findings:
                severity = finding["severity"]

                if severity == "HIGH":
                    st.error(f"🚨 {finding['type']} - HIGH RISK")
                elif severity == "MEDIUM":
                    st.warning(f"⚠ {finding['type']} - MEDIUM RISK")
                else:
                    st.info(f"ℹ {finding['type']} - LOW RISK")

                st.write(f"Endpoint: {finding['endpoint']}")
                st.write(f"Description: {finding['description']}")
                st.markdown("---")
        else:
            st.success("NO THREATS DETECTED.")

        # =========================
        # DOWNLOADS
        # =========================
        pdf_file = generate_pdf(report, url, endpoint)

        st.download_button(
            "⬇ DOWNLOAD PDF REPORT",
            data=pdf_file,
            file_name="scan_report.pdf",
            mime="application/pdf"
        )

        st.download_button(
            "⬇ DOWNLOAD JSON REPORT",
            report.to_json(),
            file_name="scan_report.json",
            mime="application/json"
        )

# =========================
# RECENT SCANS TABLE
# =========================
st.subheader("📜 Recent Scans")

if st.session_state.scan_history:
    history_df = pd.DataFrame(st.session_state.scan_history)
    st.dataframe(history_df, use_container_width=True)
else:
    st.info("No scans performed yet.")