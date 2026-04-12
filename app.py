import asyncio
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from io import BytesIO

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

from scanner.core.engine import ScanConfig, run_scan
from scanner.report import Report
from scanner.database import save_scan, fetch_all_scans, fetch_vulnerabilities, fetch_all_vulnerabilities, delete_scan

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(page_title="API Security Scanner", layout="wide", page_icon="🔐")

# =========================
# CYBERPUNK CSS
# =========================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
html, body, .stApp { background-color: #0d0d0d; color: #00ffcc; font-family: 'Share Tech Mono', monospace; }
h1, h2, h3 { color: #ff00ff; text-shadow: 0 0 10px #ff00ff; }
.stTextInput > div > div > input {
    background-color: #111 !important; color: #00ffcc !important;
    border: 1px solid #00ffcc !important;
}
.stButton > button {
    background-color: black; color: #00ffcc; border: 2px solid #00ffcc;
    box-shadow: 0 0 10px #00ffcc; font-family: 'Share Tech Mono', monospace;
}
.stButton > button:hover { background-color: #00ffcc; color: black; box-shadow: 0 0 20px #00ffcc; }
[data-testid="stMetric"] {
    background-color: #111; border: 1px solid #ff00ff; padding: 15px;
    border-radius: 10px; box-shadow: 0 0 12px #ff00ff;
}
section[data-testid="stSidebar"] { background-color: #0a0a0a; border-right: 1px solid #00ffcc; }
[data-testid="stDataFrame"] { border: 1px solid #00ffcc; }
.stTabs [data-baseweb="tab"] { color: #00ffcc; background: #111; }
.stTabs [aria-selected="true"] { border-bottom: 2px solid #ff00ff; }
</style>
""", unsafe_allow_html=True)

# =========================
# SIDEBAR
# =========================
st.sidebar.title("⚡ CYBER SECURITY TERMINAL")
st.sidebar.markdown("System Status: 🟢 **ONLINE**")
st.sidebar.markdown("---")
st.sidebar.info("OWASP API Top 10 | Async Engine v2.0")

# =========================
# PDF GENERATOR
# =========================
def generate_pdf(report, url, endpoint):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    elements = [
        Paragraph("<b>API Security Scan Report</b>", styles["Title"]),
        Spacer(1, 0.5 * inch),
        Paragraph(f"Target: {url}", styles["Normal"]),
        Paragraph(f"Endpoint: {endpoint}", styles["Normal"]),
        Spacer(1, 0.5 * inch),
    ]

    if report.findings:
        for f in report.findings:
            elements.append(Paragraph(f"<b>{f.get('title', 'N/A')} — {f.get('severity', '')}</b>", styles["Normal"]))
            elements.append(Paragraph(f"Endpoint: {f.get('endpoint', '')}", styles["Normal"]))
            elements.append(Paragraph(f"Description: {f.get('description', '')}", styles["Normal"]))
            elements.append(Spacer(1, 0.3 * inch))
    else:
        elements.append(Paragraph("No vulnerabilities detected.", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer


# =========================
# ASYNC SCAN RUNNER (via shared engine)
# =========================
async def run_scan_async(url: str, endpoint: str, token: str | None):
    """Thin wrapper — delegates to scanner.core.engine.run_scan."""
    config = ScanConfig(url=url, endpoint=endpoint, token=token, persist=True)
    return await run_scan(config)


# =========================
# TABS
# =========================
st.title("🔐 API SECURITY SCANNER")

tabs = st.tabs(["🚀 New Scan", "📜 Scan History", "🛡 All Vulnerabilities"])

# ========================= TAB 1: NEW SCAN =========================
with tabs[0]:
    st.subheader("Configure & Initiate Scan")

    col1, col2 = st.columns(2)
    with col1:
        url = st.text_input("Target Base URL", placeholder="https://api.example.com")
    with col2:
        endpoint = st.text_input("Endpoint", placeholder="/users/1")

    token = st.text_input("Bearer Token (Optional)", type="password")
    run_scan = st.button("🚀 INITIATE SCAN", use_container_width=True)

    if run_scan:
        if not url or not endpoint:
            st.error("⛔ TARGET PARAMETERS MISSING. Provide both URL and Endpoint.")
        else:
            with st.spinner("🔍 Scanning target system..."):
                headers = {}
                if token:
                    headers["Authorization"] = f"Bearer {token}"

                try:
                    result = asyncio.run(run_scan_async(url, endpoint, token or None))
                except RuntimeError:
                    import nest_asyncio
                    nest_asyncio.apply()
                    result = asyncio.get_event_loop().run_until_complete(
                        run_scan_async(url, endpoint, token or None)
                    )

            st.success("⚡ SCAN COMPLETE")

            st.caption(f"Scan `#{result.scan_id}` persisted to database.")

            # Metrics
            st.subheader("⚡ THREAT SUMMARY")
            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("TOTAL", result.total)
            mc2.metric("🔴 HIGH", result.high)
            mc3.metric("🟠 MEDIUM", result.medium)
            mc4.metric("🟢 LOW", result.low)

            if result.total > 0:
                st.subheader("⚡ THREAT DISTRIBUTION")
                fig, ax = plt.subplots(facecolor="#0d0d0d")
                ax.set_facecolor("#0d0d0d")
                colors = ["#ff2244", "#ff8800", "#00cc66"]
                counts = [result.high, result.medium, result.low]
                non_zero = [(l, v, c) for l, v, c in zip(["HIGH", "MEDIUM", "LOW"], counts, colors) if v > 0]
                if non_zero:
                    ax.pie(
                        [x[1] for x in non_zero],
                        labels=[x[0] for x in non_zero],
                        colors=[x[2] for x in non_zero],
                        autopct="%1.1f%%",
                        textprops={"color": "#00ffcc"},
                    )
                st.pyplot(fig)

            st.subheader("⚡ DETECTED VULNERABILITIES")
            if result.findings:
                for f in result.findings:
                    sev = f.get("severity", "LOW")
                    title = f.get("title", "Vulnerability")
                    if sev == "HIGH":
                        st.error(f"🚨 {title} — HIGH RISK")
                    elif sev == "MEDIUM":
                        st.warning(f"⚠ {title} — MEDIUM RISK")
                    else:
                        st.info(f"ℹ {title} — LOW RISK")
                    st.write(f"**Endpoint:** {f.get('endpoint', endpoint)}")
                    st.write(f"**Description:** {f.get('description', '')}")
                    st.markdown("---")
            else:
                st.success("✅ NO THREATS DETECTED.")

            # Downloads — build a lightweight Report object for PDF
            col_dl1, col_dl2 = st.columns(2)
            _tmp_report = Report(target=url)
            _tmp_report.findings = result.findings
            with col_dl1:
                pdf_file = generate_pdf(_tmp_report, url, endpoint)
                st.download_button("⬇ DOWNLOAD PDF", data=pdf_file, file_name="scan_report.pdf", mime="application/pdf")
            with col_dl2:
                st.download_button("⬇ DOWNLOAD JSON", _tmp_report.to_json(), file_name="scan_report.json", mime="application/json")


# ========================= TAB 2: SCAN HISTORY =========================
with tabs[1]:
    st.subheader("📜 All Past Scans")

    scans = fetch_all_scans()

    if not scans:
        st.info("No scans in the database yet. Run a scan first.")
    else:
        df = pd.DataFrame(scans)
        df.rename(columns={
            "id": "Scan ID", "target": "Target", "endpoint": "Endpoint",
            "scanned_at": "Date", "total": "Total", "high": "High",
            "medium": "Medium", "low": "Low"
        }, inplace=True)
        st.dataframe(df, use_container_width=True)

        st.markdown("---")
        st.subheader("🔍 Inspect Scan Findings")

        scan_ids = [s["id"] for s in scans]
        selected_id = st.selectbox("Select Scan ID to inspect:", scan_ids)

        if selected_id:
            vulns = fetch_vulnerabilities(selected_id)
            if vulns:
                vuln_df = pd.DataFrame(vulns)
                vuln_df.drop(columns=["scan_id", "id"], errors="ignore", inplace=True)
                st.dataframe(vuln_df, use_container_width=True)
            else:
                st.success("✅ No vulnerabilities recorded for this scan.")

        st.markdown("---")
        st.subheader("🗑 Delete a Scan Record")
        del_id = st.number_input("Enter Scan ID to delete:", min_value=1, step=1)
        if st.button("🗑 Confirm Delete", type="secondary"):
            try:
                delete_scan(int(del_id))
                st.success(f"Scan #{del_id} deleted.")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to delete: {e}")


# ========================= TAB 3: ALL VULNERABILITIES =========================
with tabs[2]:
    st.subheader("🛡 Global Vulnerability Analytics")

    all_vulns = fetch_all_vulnerabilities()

    if not all_vulns:
        st.info("No vulnerabilities found in the database.")
    else:
        df_all = pd.DataFrame(all_vulns)
        df_all.drop(columns=["id", "scan_id"], errors="ignore", inplace=True)
        df_all.rename(columns={
            "severity": "Severity", "title": "Title", "endpoint": "Endpoint",
            "description": "Description", "target": "Target", "scanned_at": "Date"
        }, inplace=True)

        # Summary metrics
        total_vulns = len(df_all)
        high_count = (df_all["Severity"] == "HIGH").sum()
        med_count = (df_all["Severity"] == "MEDIUM").sum()
        low_count = (df_all["Severity"] == "LOW").sum()

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Vulnerabilities", total_vulns)
        m2.metric("🔴 High", high_count)
        m3.metric("🟠 Medium", med_count)
        m4.metric("🟢 Low", low_count)

        st.markdown("---")

        # Filter
        sev_filter = st.multiselect("Filter by Severity:", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"])
        filtered = df_all[df_all["Severity"].isin(sev_filter)]
        st.dataframe(filtered, use_container_width=True)