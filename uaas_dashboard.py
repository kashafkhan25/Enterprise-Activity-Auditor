import json
import pandas as pd
import streamlit as st
from cryptography.fernet import Fernet

# --- Page Layout Configuration ---
st.set_page_config(
    page_title="UAAS - Enterprise Audit Terminal",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ User Activity Auditing System (UAAS)")
st.subheader("Enterprise Endpoint Telemetry Forensics Cloud Dashboard")
st.markdown("---")

# --- Cloud Safe Cryptography Decryption Pipeline ---
def load_and_decrypt_logs(uploaded_log, uploaded_key) -> list:
    """Reads uploaded encrypted telemetry streams using the provided memory key."""
    try:
        cipher_key = uploaded_key.read()
        cipher = Fernet(cipher_key)
        
        encrypted_data = uploaded_log.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Reset file pointers so user can re-read them if needed
        uploaded_log.seek(0)
        uploaded_key.seek(0)
        
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        st.sidebar.error(f"Cryptographic Processing Disruption: {e}")
        return []

# --- System Diagnostics Sidebar Controls ---
with st.sidebar:
    st.write("⚙️ ### Secure Admin Gateway")
    st.caption("Upload endpoint telemetry locks to open reporting frames.")
    
    # Cloud file drop nodes
    uploaded_log = st.file_uploader("Upload Telemetry Log (.enc)", type=["enc"])
    uploaded_key = st.file_uploader("Upload Encryption Key (.key)", type=["key"])

# --- Main Dashboard Logic Routing ---
if not uploaded_log or not uploaded_key:
    st.info("📡 **Awaiting Cryptographic Credentials Gateway Verification.** Please use the sidebar interface to upload an endpoint `activity_log.enc` data payload combined with its administrative `fernet.key` string file.")
else:
    raw_logs = load_and_decrypt_logs(uploaded_log, uploaded_key)

    if not raw_logs:
        st.error("❌ Decryption Validation Error: Key mismatch or corrupted archive payload data.")
    else:
        df = pd.DataFrame(raw_logs)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="Total Logged Input Actions", value=len(df))
        with col2:
            st.metric(label="Monitored Unique Workspaces", value=df['window'].nunique())
        with col3:
            st.metric(label="Last Connection Transmission", value=df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S PKT'))

        st.markdown("---")
        chart_col, data_col = st.columns(2)

        with chart_col:
            st.write("📊 ### Active Core Window Matrix Distribution")
            window_counts = df['window'].value_counts().reset_index()
            window_counts.columns = ['Application Window Title', 'Key Interaction Cycles']
            st.bar_chart(data=window_counts, x='Application Window Title', y='Key Interaction Cycles', width="stretch")

        with data_col:
            st.write("🔍 ### Contextual Forensic Audit Trail")
            display_df = df.copy()
            display_df['timestamp'] = display_df['timestamp'].dt.strftime('%H:%M:%S')
            st.dataframe(
                display_df[['timestamp', 'window', 'text']].sort_index(ascending=False), 
                width="stretch", 
                hide_index=True
            )
