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

st.set_page_config(
    page_title="ECLIPSIS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CUSTOM CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@300;400;600&display=swap');

/* Global dark background */
html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
    background-color: #060d1a !important;
    color: #c8d8e8 !important;
}

[data-testid="stSidebar"] {
    background-color: #080f1f !important;
    border-right: 1px solid #0e2a4a !important;
}

/* Header */
.cyber-header {
    font-family: 'Share Tech Mono', monospace;
    text-align: center;
    padding: 1.5rem 0 0.5rem 0;
}
.cyber-header h1 {
    font-size: 2.4rem;
    color: #00d4ff;
    text-shadow: 0 0 18px rgba(0,212,255,0.4);
    letter-spacing: 3px;
    margin: 0;
}
.cyber-header p {
    color: #4a7a9b;
    font-size: 0.85rem;
    letter-spacing: 2px;
    margin-top: 4px;
    text-transform: uppercase;
}

/* Divider */
.cyber-divider {
    border: none;
    border-top: 1px solid #0e2a4a;
    margin: 1rem 0;
}

/* Metric cards */
.metric-card {
    background: linear-gradient(135deg, #0a1628 0%, #0d1f3c 100%);
    border: 1px solid #0e2a4a;
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
    text-align: center;
    position: relative;
    overflow: hidden;
}
.metric-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #00d4ff, transparent);
}
.metric-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    color: #4a7a9b;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 0.4rem;
}
.metric-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2rem;
    color: #00d4ff;
    text-shadow: 0 0 12px rgba(0,212,255,0.3);
}
.metric-value.threat { color: #ff4455; text-shadow: 0 0 12px rgba(255,68,85,0.3); }
.metric-value.blocked { color: #ff8c00; text-shadow: 0 0 12px rgba(255,140,0,0.3); }
.metric-value.safe { color: #00e676; text-shadow: 0 0 12px rgba(0,230,118,0.3); }

/* Section headers */
.section-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    color: #00d4ff;
    letter-spacing: 3px;
    text-transform: uppercase;
    border-left: 3px solid #00d4ff;
    padding-left: 10px;
    margin: 1.2rem 0 0.8rem 0;
}

/* Status badges */
.badge-safe {
    background: rgba(0,230,118,0.1);
    border: 1px solid rgba(0,230,118,0.3);
    color: #00e676;
    padding: 2px 8px;
    border-radius: 4px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
}
.badge-threat {
    background: rgba(255,68,85,0.1);
    border: 1px solid rgba(255,68,85,0.3);
    color: #ff4455;
    padding: 2px 8px;
    border-radius: 4px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
}

/* Alert cards */
.alert-card {
    background: rgba(255,68,85,0.05);
    border: 1px solid rgba(255,68,85,0.2);
    border-left: 3px solid #ff4455;
    border-radius: 6px;
    padding: 0.8rem 1rem;
    margin-bottom: 0.6rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.8rem;
}
.alert-card .attack-type { color: #ff4455; font-size: 0.9rem; font-weight: bold; }
.alert-card .detail { color: #7a9bb5; margin-top: 2px; }

/* No threat card */
.safe-card {
    background: rgba(0,230,118,0.04);
    border: 1px solid rgba(0,230,118,0.15);
    border-left: 3px solid #00e676;
    border-radius: 6px;
    padding: 1rem;
    text-align: center;
    font-family: 'Share Tech Mono', monospace;
    color: #00e676;
    font-size: 0.85rem;
}

/* Start button */
.stButton > button {
    background: linear-gradient(135deg, #003d5c, #005580) !important;
    color: #00d4ff !important;
    border: 1px solid #00d4ff !important;
    border-radius: 6px !important;
    font-family: 'Share Tech Mono', monospace !important;
    letter-spacing: 2px !important;
    font-size: 0.9rem !important;
    padding: 0.6rem 1.5rem !important;
    transition: all 0.2s !important;
    text-transform: uppercase !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #005580, #0077a8) !important;
    box-shadow: 0 0 16px rgba(0,212,255,0.25) !important;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    border: 1px solid #0e2a4a !important;
    border-radius: 6px !important;
}

/* Sidebar text */
.sidebar-ip {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.8rem;
    color: #ff4455;
    background: rgba(255,68,85,0.08);
    border: 1px solid rgba(255,68,85,0.2);
    border-radius: 4px;
    padding: 4px 8px;
    margin-bottom: 4px;
}

/* Slider and checkbox */
[data-testid="stSlider"] label, [data-testid="stCheckbox"] label {
    color: #7a9bb5 !important;
    font-size: 0.8rem !important;
}

/* Status line at bottom */
.status-line {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    color: #2a4a6a;
    text-align: center;
    padding-top: 1rem;
    letter-spacing: 1px;
}
</style>
""", unsafe_allow_html=True)

# ── LOAD MODEL ─────────────────────────────────────────────────────────────────
@st.cache_resource
def load_model():
    model = joblib.load('threat_detection_model_15class.pkl')
    scaler = joblib.load('scaler_15class.pkl')
    le = joblib.load('label_encoder_15class.pkl')
    top_features = pd.read_csv('top_features_full.csv')['0'].tolist()
    return model, scaler, le, top_features

model, scaler, le, top_features = load_model()
label_map = {i: label for i, label in enumerate(le.classes_)}

# ── SESSION STATE ──────────────────────────────────────────────────────────────
for key, default in [
    ('blocked_ips', set()), ('alerts', []),
    ('total_flows', 0), ('total_threats', 0), ('monitoring_log', [])
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ── HELPERS ────────────────────────────────────────────────────────────────────
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
            src, dst = pkt['IP'].src, pkt['IP'].dst
            sport, dport = pkt['TCP'].sport, pkt['TCP'].dport
            flow_key = tuple(sorted([f"{src}:{sport}", f"{dst}:{dport}"]))
            flows[flow_key].append({
                'time': pkt.time, 'length': len(pkt),
                'flags': str(pkt['TCP'].flags),
                'src': src, 'dst': dst, 'sport': sport, 'dport': dport
            })
    return flows, len(packets)

def extract_features(flows):
    rows = []
    for flow_key, pkts in flows.items():
        if len(pkts) < 2:
            continue
        ps = sorted(pkts, key=lambda x: x['time'])
        dur = (ps[-1]['time'] - ps[0]['time']) * 1_000_000 or 1
        fsrc = ps[0]['src']
        fwd = [p for p in ps if p['src'] == fsrc]
        bwd = [p for p in ps if p['src'] != fsrc]
        fl = [p['length'] for p in fwd] or [0]
        bl = [p['length'] for p in bwd] or [0]
        al = [p['length'] for p in ps]
        ts = [p['time'] for p in ps]
        iat = [ts[i+1]-ts[i] for i in range(len(ts)-1)] or [0]
        rows.append({
            'attacker_ip': ps[0]['src'], 'dest_port': ps[0]['dport'],
            'Total_Length_of_Bwd_Packets': sum(bl),
            'Packet_Length_Variance': np.var(al),
            'Fwd_Packet_Length_Max': max(fl),
            'Subflow_Fwd_Bytes': sum(fl),
            'Packet_Length_Std': np.std(al),
            'Bwd_Packet_Length_Mean': np.mean(bl),
            'Max_Packet_Length': max(al),
            'Subflow_Bwd_Bytes': sum(bl),
            'Average_Packet_Size': np.mean(al),
            'Destination_Port': ps[0]['dport'],
            'Init_Win_bytes_forward': fl[0],
            'Avg_Bwd_Segment_Size': np.mean(bl),
            'Packet_Length_Mean': np.mean(al),
            'Total_Length_Fwd_Packets': sum(fl),
            'Bwd_Packet_Length_Std': np.std(bl),
            'PSH_Flag_Count': sum(1 for p in fwd if 'P' in p['flags']),
            'Total_Backward_Packets': len(bwd),
            'Subflow_Fwd_Packets': len(fwd),
            'Fwd_Header_Length': len(fwd) * 20,
            'Fwd_Header_Length_1': len(fwd) * 20,
        })
    return pd.DataFrame(rows)

def block_ip(ip):
    if ip in st.session_state.blocked_ips:
        return False
    try:
        rule = f"CyberShield_{ip.replace('.','_')}"
        cmd = ['netsh','advfirewall','firewall','add','rule',
               f'name={rule}','dir=in','action=block',f'remoteip={ip}','enable=yes']
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            st.session_state.blocked_ips.add(ip)
            return True
    except:
        pass
    return False

def run_monitoring(duration):
    flows, pkt_count = capture_flows(duration)
    df = extract_features(flows)
    if len(df) == 0:
        return [], pkt_count
    ips = df['attacker_ip'].values
    ports = df['dest_port'].values
    df2 = df.drop(['attacker_ip','dest_port'], axis=1)
    df2 = df2.rename(columns=column_mapping)[top_features]
    preds = model.predict(scaler.transform(df2))
    probas = model.predict_proba(scaler.transform(df2))
    results = []
    for pred, proba, ip, port in zip(preds, probas, ips, ports):
        label = label_map[pred]
        conf = max(proba) * 100
        r = {'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
             'source_ip': ip, 'port': int(port),
             'prediction': label, 'confidence': conf, 'blocked': False}
        if label != 'BENIGN':
            r['blocked'] = block_ip(ip)
            st.session_state.total_threats += 1
            st.session_state.alerts.append({
                'time': r['timestamp'], 'ip': ip,
                'attack': label, 'port': int(port),
                'confidence': conf, 'blocked': r['blocked']
            })
        results.append(r)
    st.session_state.total_flows += len(results)
    st.session_state.monitoring_log.extend(results)
    return results, pkt_count

# ── HEADER ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="cyber-header">
    <h1>⬡ CYBERSHIELD IPS</h1>
    <p>AI-Powered Intrusion Detection &amp; Prevention System</p>
</div>
<hr class="cyber-divider">
""", unsafe_allow_html=True)

# ── METRICS ────────────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">Flows Analyzed</div>
        <div class="metric-value">{st.session_state.total_flows}</div>
    </div>""", unsafe_allow_html=True)
with c2:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">Threats Detected</div>
        <div class="metric-value threat">{st.session_state.total_threats}</div>
    </div>""", unsafe_allow_html=True)
with c3:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">IPs Blocked</div>
        <div class="metric-value blocked">{len(st.session_state.blocked_ips)}</div>
    </div>""", unsafe_allow_html=True)
with c4:
    safe = st.session_state.total_flows - st.session_state.total_threats
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">Safe Flows</div>
        <div class="metric-value safe">{safe}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<hr class='cyber-divider'>", unsafe_allow_html=True)

# ── SIDEBAR ────────────────────────────────────────────────────────────────────
st.sidebar.markdown("""
<div style='font-family:"Share Tech Mono",monospace; color:#00d4ff;
     font-size:0.85rem; letter-spacing:2px; padding:0.5rem 0;'>
⬡ CONTROL PANEL
</div>
<hr style='border-color:#0e2a4a; margin:0.5rem 0;'>
""", unsafe_allow_html=True)

duration = st.sidebar.slider("Capture Duration (sec)", 5, 30, 10)
auto_block = st.sidebar.checkbox("Auto-block detected threats", value=True)

st.sidebar.markdown("""
<hr style='border-color:#0e2a4a; margin:0.8rem 0;'>
<div style='font-family:"Share Tech Mono",monospace; color:#ff4455;
     font-size:0.72rem; letter-spacing:2px;'>BLOCKED IPs</div>
""", unsafe_allow_html=True)

if st.session_state.blocked_ips:
    for ip in st.session_state.blocked_ips:
        st.sidebar.markdown(f"<div class='sidebar-ip'>❌ {ip}</div>", unsafe_allow_html=True)
else:
    st.sidebar.markdown("""
    <div style='font-family:"Share Tech Mono",monospace; color:#2a6a4a;
         font-size:0.78rem; padding:6px 0;'>— No IPs blocked —</div>
    """, unsafe_allow_html=True)

st.sidebar.markdown("<hr style='border-color:#0e2a4a; margin:0.8rem 0;'>", unsafe_allow_html=True)
if st.sidebar.button("🗑 Clear All Logs"):
    for k, v in [('alerts',[]),('monitoring_log',[]),('total_flows',0),('total_threats',0)]:
        st.session_state[k] = v
    st.rerun()

# ── MAIN LAYOUT ────────────────────────────────────────────────────────────────
left, right = st.columns([3, 2])

with left:
    st.markdown("<div class='section-label'>Live Monitoring</div>", unsafe_allow_html=True)

    if st.button("▶  START MONITORING", type="primary", use_container_width=True):
        with st.spinner(f"Scanning network for {duration} seconds..."):
            results, pkt_count = run_monitoring(duration)

        threats = [r for r in results if r['prediction'] != 'BENIGN']

        if threats:
            for t in threats:
                st.markdown(f"""
                <div class='alert-card'>
                    <div class='attack-type'>🚨 {t['prediction'].upper()}</div>
                    <div class='detail'>Source: {t['source_ip']} &nbsp;|&nbsp; Port: {t['port']} &nbsp;|&nbsp; Confidence: {t['confidence']:.1f}%</div>
                    <div class='detail'>{"🚫 IP BLOCKED" if t['blocked'] else "⚠️ ALERT ONLY"}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class='safe-card'>
                ✅ &nbsp; {pkt_count} packets captured — {len(results)} flows — all clear
            </div>""", unsafe_allow_html=True)

    st.markdown("<div class='section-label' style='margin-top:1.5rem;'>Monitoring Log</div>", unsafe_allow_html=True)

    if st.session_state.monitoring_log:
        df_log = pd.DataFrame(st.session_state.monitoring_log)
        df_log['status'] = df_log['prediction'].apply(
            lambda x: '🚨 THREAT' if x != 'BENIGN' else '✅ SAFE')
        st.dataframe(
            df_log[['timestamp','source_ip','port','prediction','confidence','status']].rename(columns={
                'timestamp':'Time','source_ip':'Source IP','port':'Port',
                'prediction':'Classification','confidence':'Confidence %','status':'Status'
            }),
            use_container_width=True, hide_index=True
        )
    else:
        st.markdown("""
        <div style='font-family:"Share Tech Mono",monospace; color:#2a4a6a;
             font-size:0.8rem; padding:2rem; text-align:center; border:1px dashed #0e2a4a;
             border-radius:6px;'>
            No data yet — press START MONITORING to begin
        </div>""", unsafe_allow_html=True)

with right:
    st.markdown("<div class='section-label'>Recent Alerts</div>", unsafe_allow_html=True)

    if st.session_state.alerts:
        for alert in reversed(st.session_state.alerts[-4:]):
            st.markdown(f"""
            <div class='alert-card'>
                <div class='attack-type'>⚡ {alert['attack']}</div>
                <div class='detail'>📍 {alert['ip']} &nbsp; 🔌 Port {alert['port']}</div>
                <div class='detail'>📊 {alert['confidence']:.1f}% confidence &nbsp; 🕐 {alert['time']}</div>
                <div class='detail'>{'🚫 BLOCKED' if alert['blocked'] else '⚠️ FLAGGED'}</div>
            </div>""", unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class='safe-card'>
            ✅ &nbsp; No threats detected
        </div>""", unsafe_allow_html=True)

    st.markdown("<div class='section-label' style='margin-top:1.2rem;'>Traffic Distribution</div>", unsafe_allow_html=True)

    if st.session_state.monitoring_log:
        df_chart = pd.DataFrame(st.session_state.monitoring_log)
        counts = df_chart['prediction'].value_counts()
        colors = ['#00e676' if l == 'BENIGN' else '#ff4455' for l in counts.index]
        fig = go.Figure(go.Pie(
            labels=counts.index, values=counts.values,
            marker=dict(colors=colors,
                       line=dict(color='#060d1a', width=2)),
            textfont=dict(family='Share Tech Mono', size=11, color='white'),
            hole=0.4
        ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(t=10, b=10, l=10, r=10),
            height=260,
            showlegend=True,
            legend=dict(font=dict(family='Share Tech Mono', size=10, color='#7a9bb5'),
                       bgcolor='rgba(0,0,0,0)')
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.markdown("""
        <div style='font-family:"Share Tech Mono",monospace; color:#2a4a6a;
             font-size:0.78rem; padding:1.5rem; text-align:center; border:1px dashed #0e2a4a;
             border-radius:6px;'>
            Chart appears after first scan
        </div>""", unsafe_allow_html=True)

# ── FOOTER ─────────────────────────────────────────────────────────────────────
st.markdown("<hr class='cyber-divider'>", unsafe_allow_html=True)
st.markdown(f"""
<div class='status-line'>
    CYBERSHIELD IPS &nbsp;|&nbsp; AI MODEL: RANDOM FOREST 15-CLASS &nbsp;|&nbsp;
    SESSION: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp;
    STATUS: OPERATIONAL
</div>
""", unsafe_allow_html=True)