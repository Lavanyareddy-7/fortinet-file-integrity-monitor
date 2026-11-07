
import streamlit as st
import hashlib
import pandas as pd
from datetime import datetime

st.set_page_config(
    page_title="Fortinet Firewall Lions",
    page_icon="🛡️",
    layout="wide"
)

# ---------- Styling ----------
st.markdown("""
<style>
.stApp {
    background-color: #101827;
    color: white;
}
h1, h2, h3, p, label {
    color: white !important;
}
div[data-testid="stMetric"] {
    background: #1d2b40;
    padding: 16px;
    border-radius: 12px;
}
.stButton button {
    background-color: #e63946;
    color: white;
    border-radius: 8px;
    border: none;
}
</style>
""", unsafe_allow_html=True)

# ---------- Session State ----------
if "baseline" not in st.session_state:
    st.session_state.baseline = None

if "baseline_name" not in st.session_state:
    st.session_state.baseline_name = None

if "history" not in st.session_state:
    st.session_state.history = []

# ---------- Hash Function ----------
def calculate_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

# ---------- Header ----------
st.title("🛡️ FORTINET FIREWALL LIONS")
st.subheader("File Integrity Monitoring Center")
st.caption("Defend the network. Protect the data. Rule the pitch.")

st.divider()

# ---------- Sidebar ----------
st.sidebar.title("Security Control Center")
page = st.sidebar.radio(
    "Navigate",
    ["Dashboard", "File Integrity Scanner", "Scan History", "About"]
)

# ---------- Dashboard ----------
if page == "Dashboard":
    st.header("Security Dashboard")
    st.write(
        "Monitor file integrity using SHA-256 cryptographic hashing."
    )

    total = len(st.session_state.history)
    passed = sum(
        1 for item in st.session_state.history
        if item["Result"] == "PASS"
    )
    alerts = sum(
        1 for item in st.session_state.history
        if item["Result"] == "ALERT"
    )

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Scans", total)
    c2.metric("Passed Checks", passed)
    c3.metric("Integrity Alerts", alerts)

    st.subheader("Latest Security Activity")

    if st.session_state.history:
        df = pd.DataFrame(st.session_state.history)
        st.dataframe(df.tail(10), use_container_width=True)
    else:
        st.info("No scans yet. Visit File Integrity Scanner to begin.")

    if total:
        st.subheader("Scan Result Analytics")
        chart_data = pd.DataFrame({
            "Result": ["PASS", "ALERT"],
            "Count": [passed, alerts]
        }).set_index("Result")
        st.bar_chart(chart_data)

# ---------- File Integrity Scanner ----------
elif page == "File Integrity Scanner":
    st.header("SHA-256 File Integrity Scanner")

    uploaded_file = st.file_uploader(
        "Upload a file to calculate its SHA-256 hash",
        type=None
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        current_hash = calculate_sha256(file_bytes)

        st.subheader("File Information")
        st.write("**File name:**", uploaded_file.name)
        st.write("**File size:**", f"{len(file_bytes):,} bytes")

        st.write("**Current SHA-256 Hash**")
        st.code(current_hash)

        st.divider()

        if st.session_state.baseline is None:
            st.warning("No trusted baseline has been created yet.")

            if st.button("Set This File as Trusted Baseline"):
                st.session_state.baseline = current_hash
                st.session_state.baseline_name = uploaded_file.name
                st.success("Trusted baseline created for this session.")
                st.rerun()

        else:
            st.write(
                "**Trusted baseline file:**",
                st.session_state.baseline_name
            )
            st.write("**Trusted SHA-256 Hash**")
            st.code(st.session_state.baseline)

            if st.button("Verify File Integrity"):
                result = (
                    "PASS"
                    if current_hash == st.session_state.baseline
                    else "ALERT"
                )

                timestamp = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                st.session_state.history.append({
                    "Time": timestamp,
                    "File": uploaded_file.name,
                    "SHA-256": current_hash,
                    "Result": result
                })

                if result == "PASS":
                    st.success(
                        "PASS — File matches the trusted baseline."
                    )
                else:
                    st.error(
                        "ALERT — File modification detected!"
                    )

    st.divider()

    if st.button("Clear Session Baseline"):
        st.session_state.baseline = None
        st.session_state.baseline_name = None
        st.info("Session baseline cleared.")
        st.rerun()

# ---------- Scan History ----------
elif page == "Scan History":
    st.header("Security Scan History")

    if st.session_state.history:
        df = pd.DataFrame(st.session_state.history)
        st.dataframe(df, use_container_width=True)

        csv = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "Download Scan History (CSV)",
            data=csv,
            file_name="fortinet_scan_history.csv",
            mime="text/csv"
        )
    else:
        st.info("No scan records are available yet.")

# ---------- About ----------
elif page == "About":
    st.header("About This Project")

    st.write("""
    **Fortinet Firewall Lions – File Integrity Monitoring Center**

    This educational cybersecurity prototype demonstrates how
    SHA-256 cryptographic hashing can help identify changes in files.

    **Security workflow:**
    1. Upload a file.
    2. Calculate its SHA-256 hash.
    3. Establish a trusted baseline.
    4. Upload a file for verification.
    5. Compare the current hash with the baseline.
    6. Display PASS or ALERT.

    **Important limitation:** This prototype stores its trusted
    baseline and scan history in the Streamlit session. They may
    disappear when the session resets. It is not a production
    security monitoring system.
    """)

st.divider()
st.caption("INFO 5737 | Team 3 – Fortinet Firewall Lions")
