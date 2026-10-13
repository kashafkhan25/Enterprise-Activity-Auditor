import json
from pathlib import Path
import pandas as pd
import streamlit as st
from cryptography.fernet import Fernet

# --- Page Layout Configuration ---
st.set_page_config(
    page_title="UAAS - Enterprise Audit Terminal",
    page_icon="🛡️",
    layout="wide"
)

LOG_DIR = "uaas_data"
LOG_FILE_NAME = "activity_log.enc"
KEY_FILE = "fernet.key"

log_path = Path(LOG_DIR) / LOG_FILE_NAME
key_path = Path(LOG_DIR) / KEY_FILE

st.title("🛡️ User Activity Auditing System (UAAS)")
st.subheader("Enterprise Endpoint Telemetry Forensics Dashboard")
st.markdown("---")

def load_and_decrypt_logs() -> list:
    if not log_path.exists() or not key_path.exists():
        return []
    try:
        cipher_key = key_path.read_bytes()
        cipher = Fernet(cipher_key)
        encrypted_data = log_path.read_bytes()
        if not encrypted_data:
            return []
        decrypted_data = cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        st.error(f"Cryptographic Processing Disruption: {e}")
        return []

raw_logs = load_and_decrypt_logs()

if not raw_logs:
    st.info("📡 Awaiting incoming data structures... Verify that `uaas_collector.py` is actively writing records.")
else:
    df = pd.DataFrame(raw_logs)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="Total Logged Input Actions", value=len(df))
    with col2:
        st.metric(label="Monitored Unique Workspaces", value=df['window'].nunique())
    with col3:
        # Adjusted time display format explicitly to highlight Pakistan Standard Time (PKT)
        st.metric(label="Last Connection Transmission", value=df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S PKT'))

    st.markdown("---")
    chart_col, data_col = st.columns(2)

    with chart_col:
        st.write("📊 ### Active Core Window Matrix Distribution")
        window_counts = df['window'].value_counts().reset_index()
        window_counts.columns = ['Application Window Title', 'Key Interaction Cycles']
        
        # Swapped container width logic to modern Streamlit spec rules to suppress core CLI execution warnings
        st.bar_chart(data=window_counts, x='Application Window Title', y='Key Interaction Cycles', width="stretch")

    with data_col:
        st.write("🔍 ### Contextual Forensic Audit Trail")
        display_df = df.copy()
        
        # Retains the localized hour/minute/second layout index sequence
        display_df['timestamp'] = display_df['timestamp'].dt.strftime('%H:%M:%S')
        st.dataframe(
            display_df[['timestamp', 'window', 'text']].sort_index(ascending=False), 
            width="stretch", 
            hide_index=True
        )
