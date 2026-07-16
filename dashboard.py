import streamlit as st
import pandas as pd
import numpy as np
import joblib
import datetime
import subprocess
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import sniff
from collections import defaultdict

# ─── PAGE CONFIG ───────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield IPS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ─── LOAD MODEL ────────────────────────────────────────────
@st.cache_resource
def load_model():
    model = joblib.load('threat_detection_model_15class.pkl')
    scaler = joblib.load('scaler_15class.pkl')
    le = joblib.load('label_encoder_15class.pkl')
    top_features = pd.read_csv('top_features_full.csv')['0'].tolist()
    return model, scaler, le, top_features

model, scaler, le, top_features = load_model()
label_map = {i: label for i, label in enumerate(le.classes_)}

# ─── SESSION STATE ──────────────────────────────────────────
if 'blocked_ips' not in st.session_state:
    st.session_state.blocked_ips = set()
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'total_flows' not in st.session_state:
    st.session_state.total_flows = 0
if 'total_threats' not in st.session_state:
    st.session_state.total_threats = 0
if 'monitoring_log' not in st.session_state:
    st.session_state.monitoring_log = []

# ─── HELPER FUNCTIONS ───────────────────────────────────────
column_mapping = {
    'Total_Length_of_Bwd_Packets': ' Total Length of Bwd Packets',
    'Packet_Length_Variance': ' Packet Length Variance',
    'Fwd_Packet_Length_Max': ' Fwd Packet Length Max',
    'Subflow_Fwd_Bytes': ' Subflow Fwd Bytes',
    'Packet_Length_Std': ' Packet Length Std',
    'Bwd_Packet_Length_Mean': ' Bwd Packet Length Mean',
    'Max_Packet_Length': ' Max Packet Length',
    'Subflow_Bwd_Bytes': ' Subflow Bwd Bytes',
    'Average_Packet_Size': ' Average Packet Size',
    'Destination_Port': ' Destination Port',
    'Init_Win_bytes_forward': 'Init_Win_bytes_forward',
    'Avg_Bwd_Segment_Size': ' Avg Bwd Segment Size',
    'Packet_Length_Mean': ' Packet Length Mean',
    'Total_Length_Fwd_Packets': 'Total Length of Fwd Packets',
    'Bwd_Packet_Length_Std': ' Bwd Packet Length Std',
    'PSH_Flag_Count': ' PSH Flag Count',
    'Total_Backward_Packets': ' Total Backward Packets',
    'Subflow_Fwd_Packets': 'Subflow Fwd Packets',
    'Fwd_Header_Length': ' Fwd Header Length',
    'Fwd_Header_Length_1': ' Fwd Header Length.1',
}

def capture_flows(duration=10):
    packets = sniff(timeout=duration)
    flows = defaultdict(list)
    for pkt in packets:
        if pkt.haslayer('IP') and pkt.haslayer('TCP'):
            src = pkt['IP'].src
            dst = pkt['IP'].dst
            sport = pkt['TCP'].sport
            dport = pkt['TCP'].dport
            flow_key = tuple(sorted([f"{src}:{sport}", f"{dst}:{dport}"]))
            flows[flow_key].append({
                'time': pkt.time,
                'length': len(pkt),
                'flags': str(pkt['TCP'].flags),
                'src': src,
                'dst': dst,
                'sport': sport,
                'dport': dport
            })
    return flows, len(packets)

def extract_features(flows):
    flow_features = []
    for flow_key, packets in flows.items():
        if len(packets) < 2:
            continue
        packets_sorted = sorted(packets, key=lambda x: x['time'])
        duration = (packets_sorted[-1]['time'] - packets_sorted[0]['time']) * 1_000_000
        duration = duration if duration > 0 else 1
        forward_src = packets_sorted[0]['src']
        fwd_packets = [p for p in packets_sorted if p['src'] == forward_src]
        bwd_packets = [p for p in packets_sorted if p['src'] != forward_src]
        fwd_lengths = [p['length'] for p in fwd_packets] or [0]
        bwd_lengths = [p['length'] for p in bwd_packets] or [0]
        all_lengths = [p['length'] for p in packets_sorted]
        times = [p['time'] for p in packets_sorted]
        iat = [times[i+1]-times[i] for i in range(len(times)-1)] or [0]
        psh_count_fwd = sum(1 for p in fwd_packets if 'P' in p['flags'])
        attacker_ip = packets_sorted[0]['src']
        flow_features.append({
            'attacker_ip': attacker_ip,
            'dest_port': packets_sorted[0]['dport'],
            'Total_Length_of_Bwd_Packets': sum(bwd_lengths),
            'Packet_Length_Variance': np.var(all_lengths),
            'Fwd_Packet_Length_Max': max(fwd_lengths),
            'Subflow_Fwd_Bytes': sum(fwd_lengths),
            'Packet_Length_Std': np.std(all_lengths),
            'Bwd_Packet_Length_Mean': np.mean(bwd_lengths),
            'Max_Packet_Length': max(all_lengths),
            'Subflow_Bwd_Bytes': sum(bwd_lengths),
            'Average_Packet_Size': np.mean(all_lengths),
            'Destination_Port': packets_sorted[0]['dport'],
            'Init_Win_bytes_forward': fwd_lengths[0],
            'Avg_Bwd_Segment_Size': np.mean(bwd_lengths),
            'Packet_Length_Mean': np.mean(all_lengths),
            'Total_Length_Fwd_Packets': sum(fwd_lengths),
            'Bwd_Packet_Length_Std': np.std(bwd_lengths),
            'PSH_Flag_Count': psh_count_fwd,
            'Total_Backward_Packets': len(bwd_packets),
            'Subflow_Fwd_Packets': len(fwd_packets),
            'Fwd_Header_Length': len(fwd_packets) * 20,
            'Fwd_Header_Length_1': len(fwd_packets) * 20,
        })
    return pd.DataFrame(flow_features)

def block_ip(ip):
    if ip in st.session_state.blocked_ips:
        return False
    try:
        rule_name = f"CyberShield_{ip.replace('.', '_')}"
        cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
               f'name={rule_name}', 'dir=in', 'action=block',
               f'remoteip={ip}', 'enable=yes']
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            st.session_state.blocked_ips.add(ip)
            return True
    except:
        pass
    return False

def run_monitoring(duration):
    flows, packet_count = capture_flows(duration)
    df_feat = extract_features(flows)

    if len(df_feat) == 0:
        return [], packet_count

    attacker_ips = df_feat['attacker_ip'].values
    dest_ports = df_feat['dest_port'].values
    df_model = df_feat.drop(['attacker_ip', 'dest_port'], axis=1)
    df_renamed = df_model.rename(columns=column_mapping)
    df_final = df_renamed[top_features]

    X_scaled = scaler.transform(df_final)
    predictions = model.predict(X_scaled)
    probas = model.predict_proba(X_scaled)

    results = []
    for i, (pred, proba, ip, port) in enumerate(zip(predictions, probas, attacker_ips, dest_ports)):
        label = label_map[pred]
        confidence = max(proba) * 100
        result = {
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
            'source_ip': ip,
            'port': int(port),
            'prediction': label,
            'confidence': confidence,
            'blocked': False
        }
        if label != 'BENIGN':
            blocked = block_ip(ip)
            result['blocked'] = blocked
            st.session_state.total_threats += 1
            st.session_state.alerts.append({
                'time': result['timestamp'],
                'ip': ip,
                'attack': label,
                'port': int(port),
                'confidence': confidence,
                'blocked': blocked
            })
        results.append(result)

    st.session_state.total_flows += len(results)
    st.session_state.monitoring_log.extend(results)
    return results, packet_count

# ─── DASHBOARD UI ───────────────────────────────────────────

# Header
st.markdown("""
    <h1 style='text-align:center; color:#1F4E79;'>
        🛡️ CyberShield IPS Dashboard
    </h1>
    <p style='text-align:center; color:gray;'>
        AI-Based Cyber Security Threat Detection and Intrusion Prevention System
    </p>
    <hr>
""", unsafe_allow_html=True)

# ─── TOP METRICS ────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🔍 Total Flows Analyzed", st.session_state.total_flows)
with col2:
    st.metric("🚨 Threats Detected", st.session_state.total_threats)
with col3:
    st.metric("🚫 IPs Blocked", len(st.session_state.blocked_ips))
with col4:
    safe = st.session_state.total_flows - st.session_state.total_threats
    st.metric("✅ Safe Flows", safe)

st.markdown("---")

# ─── SIDEBAR ────────────────────────────────────────────────
st.sidebar.title("⚙️ Control Panel")
st.sidebar.markdown("---")
duration = st.sidebar.slider("Capture Duration (seconds)", 5, 30, 10)
auto_block = st.sidebar.checkbox("Auto-block threats", value=True)

st.sidebar.markdown("---")
st.sidebar.subheader("🚫 Blocked IPs")
if st.session_state.blocked_ips:
    for ip in st.session_state.blocked_ips:
        st.sidebar.error(f"❌ {ip}")
else:
    st.sidebar.success("No IPs blocked")

st.sidebar.markdown("---")
if st.sidebar.button("🗑️ Clear All Logs"):
    st.session_state.alerts = []
    st.session_state.monitoring_log = []
    st.session_state.total_flows = 0
    st.session_state.total_threats = 0
    st.rerun()

# ─── MAIN CONTENT ───────────────────────────────────────────
col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("📡 Live Network Monitoring")

    if st.button("▶️ Start Monitoring", type="primary", use_container_width=True):
        with st.spinner(f"🔍 Capturing traffic for {duration} seconds..."):
            results, packet_count = run_monitoring(duration)

        st.success(f"✅ Captured {packet_count} packets — analyzed {len(results)} flows")

        if results:
            threats = [r for r in results if r['prediction'] != 'BENIGN']
            if threats:
                for t in threats:
                    st.error(f"🚨 THREAT: {t['prediction']} from {t['source_ip']} on port {t['port']} ({t['confidence']:.1f}% confidence) {'— BLOCKED' if t['blocked'] else ''}")
            else:
                st.info("✅ All flows classified as normal traffic")

    st.markdown("---")

    # Monitoring log table
    st.subheader("📋 Monitoring Log")
    if st.session_state.monitoring_log:
        df_log = pd.DataFrame(st.session_state.monitoring_log)
        df_log['status'] = df_log['prediction'].apply(
            lambda x: '🚨 THREAT' if x != 'BENIGN' else '✅ SAFE'
        )
        st.dataframe(
            df_log[['timestamp', 'source_ip', 'port', 'prediction', 'confidence', 'status']],
            use_container_width=True
        )
    else:
        st.info("No monitoring data yet. Click 'Start Monitoring' to begin!")

with col_right:
    st.subheader("🚨 Recent Alerts")
    if st.session_state.alerts:
        for alert in reversed(st.session_state.alerts[-5:]):
            st.error(f"""
            **{alert['attack']}**
            📍 IP: {alert['ip']}
            🔌 Port: {alert['port']}
            📊 Confidence: {alert['confidence']:.1f}%
            🕐 Time: {alert['time']}
            {'🚫 BLOCKED' if alert['blocked'] else '⚠️ NOT BLOCKED'}
            """)
    else:
        st.success("✅ No threats detected yet")

    st.markdown("---")

    # Traffic distribution chart
    st.subheader("📊 Traffic Distribution")
    if st.session_state.monitoring_log:
        df_log = pd.DataFrame(st.session_state.monitoring_log)
        counts = df_log['prediction'].value_counts()
        fig = px.pie(
            values=counts.values,
            names=counts.index,
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig.update_layout(margin=dict(t=0, b=0, l=0, r=0), height=300)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Traffic chart will appear after monitoring starts")

# ─── ALERTS HISTORY ─────────────────────────────────────────
st.markdown("---")
st.subheader("📜 Full Alert History")
if st.session_state.alerts:
    df_alerts = pd.DataFrame(st.session_state.alerts)
    st.dataframe(df_alerts, use_container_width=True)
else:
    st.info("No alerts recorded yet")