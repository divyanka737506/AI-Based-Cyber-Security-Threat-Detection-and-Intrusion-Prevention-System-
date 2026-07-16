import streamlit as st
import pandas as pd
import numpy as np
import joblib
import datetime
import subprocess
import time
import plotly.express as px
import plotly.graph_objects as go
import requests
from scapy.all import sniff
from collections import defaultdict

st.set_page_config(
    page_title="ECLIPSIS IPS",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CSS ────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@300;400;600&display=swap');

html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
    background-color: #060d1a !important;
    color: #c8d8e8 !important;
}
[data-testid="stSidebar"] {
    background-color: #080f1f !important;
    border-right: 1px solid #0e2a4a !important;
}
.cyber-header {
    font-family: 'Share Tech Mono', monospace;
    text-align: center;
    padding: 1.2rem 0 0.3rem 0;
}
.cyber-header h1 {
    font-size: 3rem;
    color: #00d4ff;
    text-shadow: 0 0 30px rgba(0,212,255,0.5), 0 0 60px rgba(0,212,255,0.2);
    letter-spacing: 8px;
    margin: 0;
}
.cyber-header .subtitle {
    color: #4a7a9b;
    font-size: 0.78rem;
    letter-spacing: 4px;
    margin-top: 4px;
    text-transform: uppercase;
}
.cyber-header .tagline {
    color: #1a3a5a;
    font-size: 0.65rem;
    letter-spacing: 2px;
    margin-top: 2px;
}
.cyber-divider { border: none; border-top: 1px solid #0e2a4a; margin: 0.8rem 0; }

/* Health score */
.health-ring {
    text-align: center;
    padding: 0.5rem;
}
.health-score-num {
    font-family: 'Share Tech Mono', monospace;
    font-size: 3.5rem;
    line-height: 1;
    text-shadow: 0 0 20px currentColor;
}
.health-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 3px;
    color: #4a7a9b;
    margin-top: 4px;
}
.health-status {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.85rem;
    letter-spacing: 2px;
    margin-top: 6px;
    text-transform: uppercase;
}

/* Metric cards */
.metric-card {
    background: linear-gradient(135deg, #0a1628 0%, #0d1f3c 100%);
    border: 1px solid #0e2a4a;
    border-radius: 8px;
    padding: 1rem 1.2rem;
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
    font-size: 0.65rem;
    color: #4a7a9b;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 0.3rem;
}
.metric-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.8rem;
    color: #00d4ff;
    text-shadow: 0 0 12px rgba(0,212,255,0.3);
}
.metric-value.threat { color: #ff4455; text-shadow: 0 0 12px rgba(255,68,85,0.3); }
.metric-value.blocked { color: #ff8c00; text-shadow: 0 0 12px rgba(255,140,0,0.3); }
.metric-value.safe { color: #00e676; text-shadow: 0 0 12px rgba(0,230,118,0.3); }
.metric-value.scan { color: #b388ff; text-shadow: 0 0 12px rgba(179,136,255,0.3); }

/* Section label */
.section-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.68rem;
    color: #00d4ff;
    letter-spacing: 3px;
    text-transform: uppercase;
    border-left: 3px solid #00d4ff;
    padding-left: 10px;
    margin: 1.2rem 0 0.8rem 0;
}

/* Severity badges */
.sev-critical { background:rgba(255,0,60,0.15); border:1px solid rgba(255,0,60,0.4); color:#ff003c; padding:2px 8px; border-radius:4px; font-family:'Share Tech Mono',monospace; font-size:0.7rem; }
.sev-high { background:rgba(255,68,85,0.12); border:1px solid rgba(255,68,85,0.35); color:#ff4455; padding:2px 8px; border-radius:4px; font-family:'Share Tech Mono',monospace; font-size:0.7rem; }
.sev-medium { background:rgba(255,140,0,0.12); border:1px solid rgba(255,140,0,0.35); color:#ff8c00; padding:2px 8px; border-radius:4px; font-family:'Share Tech Mono',monospace; font-size:0.7rem; }
.sev-low { background:rgba(0,212,255,0.08); border:1px solid rgba(0,212,255,0.25); color:#00d4ff; padding:2px 8px; border-radius:4px; font-family:'Share Tech Mono',monospace; font-size:0.7rem; }

/* Alert cards */
.alert-card {
    background: rgba(255,68,85,0.05);
    border: 1px solid rgba(255,68,85,0.2);
    border-left: 3px solid #ff4455;
    border-radius: 6px;
    padding: 0.7rem 1rem;
    margin-bottom: 0.5rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
}
.alert-card .attack-type { color: #ff4455; font-size: 0.88rem; font-weight: bold; }
.alert-card .detail { color: #7a9bb5; margin-top: 3px; }
.alert-card .geo { color: #b388ff; margin-top: 3px; }

/* Timeline event */
.timeline-event {
    display: flex;
    gap: 12px;
    padding: 6px 0;
    border-bottom: 1px solid #0a1a2e;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    align-items: center;
}
.timeline-time { color: #2a5a7a; min-width: 60px; }
.timeline-dot-safe { width:8px; height:8px; border-radius:50%; background:#00e676; box-shadow:0 0 6px #00e676; flex-shrink:0; }
.timeline-dot-threat { width:8px; height:8px; border-radius:50%; background:#ff4455; box-shadow:0 0 6px #ff4455; flex-shrink:0; animation: pulse 1s infinite; flex-shrink:0; }
.timeline-text-safe { color: #2a6a4a; }
.timeline-text-threat { color: #ff4455; }

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
}

/* Predictor */
.predictor-card {
    background: linear-gradient(135deg, #0d1a30, #0a1525);
    border: 1px solid #1a3a5a;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    font-family: 'Share Tech Mono', monospace;
}
.predictor-title { color: #b388ff; font-size: 0.7rem; letter-spacing: 2px; margin-bottom: 8px; }
.predictor-attack { color: #ff8c00; font-size: 1rem; margin-bottom: 4px; }
.predictor-prob { color: #4a7a9b; font-size: 0.75rem; }
.predictor-bar {
    background: #0a1525;
    border-radius: 4px;
    height: 6px;
    margin-top: 8px;
    overflow: hidden;
}
.predictor-fill {
    height: 100%;
    border-radius: 4px;
    background: linear-gradient(90deg, #b388ff, #ff8c00);
}

/* Safe card */
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

/* Button */
.stButton > button {
    background: linear-gradient(135deg, #003d5c, #005580) !important;
    color: #00d4ff !important;
    border: 1px solid #00d4ff !important;
    border-radius: 6px !important;
    font-family: 'Share Tech Mono', monospace !important;
    letter-spacing: 2px !important;
    font-size: 0.85rem !important;
    transition: all 0.2s !important;
    text-transform: uppercase !important;
}
.stButton > button:hover {
    box-shadow: 0 0 16px rgba(0,212,255,0.3) !important;
}

/* Sidebar */
.sidebar-ip {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: #ff4455;
    background: rgba(255,68,85,0.08);
    border: 1px solid rgba(255,68,85,0.2);
    border-radius: 4px;
    padding: 4px 8px;
    margin-bottom: 4px;
}
.status-line {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    color: #1a3a5a;
    text-align: center;
    padding-top: 0.8rem;
    letter-spacing: 1px;
}
</style>
""", unsafe_allow_html=True)

# ── MODEL ──────────────────────────────────────────────────────────────────────
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
defaults = {
    'blocked_ips': set(), 'alerts': [], 'total_flows': 0,
    'total_threats': 0, 'monitoring_log': [], 'scan_count': 0,
    'start_time': datetime.datetime.now(), 'timeline': [],
    'port_hits': defaultdict(int), 'attack_counts': defaultdict(int)
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

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

SEVERITY_MAP = {
    'BENIGN': ('SAFE', 'safe'),
    'DDoS': ('CRITICAL', 'critical'),
    'DoS Hulk': ('CRITICAL', 'critical'),
    'DoS GoldenEye': ('HIGH', 'high'),
    'DoS slowloris': ('HIGH', 'high'),
    'DoS Slowhttptest': ('HIGH', 'high'),
    'FTP-Patator': ('HIGH', 'high'),
    'SSH-Patator': ('HIGH', 'high'),
    'PortScan': ('MEDIUM', 'medium'),
    'Bot': ('MEDIUM', 'medium'),
    'Heartbleed': ('CRITICAL', 'critical'),
    'Infiltration': ('CRITICAL', 'critical'),
    'Web Attack - Brute Force': ('HIGH', 'high'),
    'Web Attack - Sql Injection': ('CRITICAL', 'critical'),
    'Web Attack - XSS': ('MEDIUM', 'medium'),
}

def get_severity(label):
    return SEVERITY_MAP.get(label, ('LOW', 'low'))

def get_health_score():
    if st.session_state.total_flows == 0:
        return 100
    threat_ratio = st.session_state.total_threats / max(st.session_state.total_flows, 1)
    blocked_ratio = len(st.session_state.blocked_ips) / max(st.session_state.total_threats + 1, 1)
    score = 100 - (threat_ratio * 60) - (len(st.session_state.blocked_ips) * 3)
    score = max(0, min(100, score))
    return round(score)

def get_health_color(score):
    if score >= 80: return '#00e676'
    if score >= 60: return '#ffeb3b'
    if score >= 40: return '#ff8c00'
    return '#ff4455'

def get_health_status(score):
    if score >= 80: return '● SECURE'
    if score >= 60: return '● CAUTION'
    if score >= 40: return '● WARNING'
    return '● CRITICAL'

def predict_next_threat():
    if not st.session_state.alerts:
        return None, 0
    recent = st.session_state.alerts[-10:]
    attack_types = [a['attack'] for a in recent]
    if not attack_types:
        return None, 0
    counts = defaultdict(int)
    for a in attack_types:
        counts[a] += 1
    most_common = max(counts, key=counts.get)
    prob = min(95, counts[most_common] / len(attack_types) * 100 + 20)
    return most_common, round(prob)

def get_geo(ip):
    try:
        if ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('127.'):
            return '🏠 Local Network'
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
        data = r.json()
        if data.get('status') == 'success':
            return f"🌍 {data.get('country','Unknown')} — {data.get('city','')}"
    except:
        pass
    return '🌐 Unknown Location'

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
        rule = f"ECLIPSIS_{ip.replace('.','_')}"
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
    st.session_state.scan_count += 1
    if len(df) == 0:
        return [], pkt_count
    ips = df['attacker_ip'].values
    ports = df['dest_port'].values
    df2 = df.drop(['attacker_ip','dest_port'], axis=1).rename(columns=column_mapping)[top_features]
    X = scaler.transform(df2)
    preds = model.predict(X)
    probas = model.predict_proba(X)
    results = []
    for pred, proba, ip, port in zip(preds, probas, ips, ports):
        label = label_map[pred]
        conf = max(proba) * 100
        sev_label, sev_class = get_severity(label)
        st.session_state.port_hits[int(port)] += 1
        r = {
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
            'source_ip': ip, 'port': int(port),
            'prediction': label, 'confidence': conf,
            'severity': sev_label, 'blocked': False
        }
        if label != 'BENIGN':
            r['blocked'] = block_ip(ip)
            geo = get_geo(ip)
            st.session_state.total_threats += 1
            st.session_state.attack_counts[label] += 1
            st.session_state.alerts.append({
                'time': r['timestamp'], 'ip': ip, 'attack': label,
                'port': int(port), 'confidence': conf,
                'blocked': r['blocked'], 'geo': geo,
                'severity': sev_label, 'sev_class': sev_class
            })
            st.session_state.timeline.append({
                'time': r['timestamp'], 'type': 'threat',
                'text': f"{label} from {ip}"
            })
        else:
            st.session_state.timeline.append({
                'time': r['timestamp'], 'type': 'safe',
                'text': f"Normal flow on port {int(port)}"
            })
        results.append(r)
    st.session_state.total_flows += len(results)
    st.session_state.monitoring_log.extend(results)
    return results, pkt_count

# ── HEADER ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="cyber-header">
    <h1>⬡ ECLIPSIS</h1>
    <div class="subtitle">Real-Time Network Threat Intelligence System</div>
    <div class="tagline">AI-Powered Intrusion Detection &amp; Prevention — Aarivya Labs</div>
</div>
<hr class="cyber-divider">
""", unsafe_allow_html=True)

# ── TOP METRICS ────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)
uptime = str(datetime.datetime.now() - st.session_state.start_time).split('.')[0]
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
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">Scans Run</div>
        <div class="metric-value scan">{st.session_state.scan_count}</div>
    </div>""", unsafe_allow_html=True)
with c5:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">Uptime</div>
        <div class="metric-value" style="font-size:1.2rem; padding-top:0.3rem;">{uptime}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<hr class='cyber-divider'>", unsafe_allow_html=True)

# ── SIDEBAR ────────────────────────────────────────────────────────────────────
st.sidebar.markdown("""
<div style='font-family:"Share Tech Mono",monospace; color:#00d4ff;
     font-size:0.8rem; letter-spacing:3px; padding:0.5rem 0;'>
⬡ ECLIPSIS CONTROL
</div>
<hr style='border-color:#0e2a4a; margin:0.5rem 0;'>
""", unsafe_allow_html=True)

duration = st.sidebar.slider("Capture Duration (sec)", 5, 30, 10)
auto_block = st.sidebar.checkbox("Auto-block threats", value=True)

# Health score in sidebar
score = get_health_score()
color = get_health_color(score)
status = get_health_status(score)
st.sidebar.markdown(f"""
<hr style='border-color:#0e2a4a; margin:0.8rem 0;'>
<div class="health-ring">
    <div class="metric-label">Network Health</div>
    <div class="health-score-num" style="color:{color}">{score}</div>
    <div class="health-label">/ 100</div>
    <div class="health-status" style="color:{color}">{status}</div>
</div>
<hr style='border-color:#0e2a4a; margin:0.8rem 0;'>
""", unsafe_allow_html=True)

# Threat predictor in sidebar
next_attack, prob = predict_next_threat()
st.sidebar.markdown("""
<div style='font-family:"Share Tech Mono",monospace; color:#b388ff;
     font-size:0.68rem; letter-spacing:2px; margin-bottom:6px;'>
⟳ THREAT PREDICTOR
</div>""", unsafe_allow_html=True)
if next_attack:
    st.sidebar.markdown(f"""
    <div class="predictor-card">
        <div class="predictor-title">NEXT LIKELY ATTACK</div>
        <div class="predictor-attack">{next_attack}</div>
        <div class="predictor-prob">Probability: {prob}%</div>
        <div class="predictor-bar">
            <div class="predictor-fill" style="width:{prob}%"></div>
        </div>
    </div>""", unsafe_allow_html=True)
else:
    st.sidebar.markdown("""
    <div class="predictor-card">
        <div class="predictor-title">NEXT LIKELY ATTACK</div>
        <div style="color:#2a5a7a; font-size:0.78rem;">Insufficient data — run more scans</div>
    </div>""", unsafe_allow_html=True)

st.sidebar.markdown("""
<hr style='border-color:#0e2a4a; margin:0.8rem 0;'>
<div style='font-family:"Share Tech Mono",monospace; color:#ff4455;
     font-size:0.68rem; letter-spacing:2px; margin-bottom:6px;'>
🚫 BLOCKED IPs
</div>""", unsafe_allow_html=True)
if st.session_state.blocked_ips:
    for ip in st.session_state.blocked_ips:
        st.sidebar.markdown(f"<div class='sidebar-ip'>❌ {ip}</div>", unsafe_allow_html=True)
else:
    st.sidebar.markdown("""<div style='font-family:"Share Tech Mono",monospace;
        color:#1a4a2a; font-size:0.75rem; padding:4px 0;'>— None blocked —</div>""",
        unsafe_allow_html=True)

st.sidebar.markdown("<hr style='border-color:#0e2a4a; margin:0.8rem 0;'>", unsafe_allow_html=True)
if st.sidebar.button("🗑 Clear Session"):
    for k, v in [('alerts',[]),('monitoring_log',[]),('total_flows',0),
                 ('total_threats',0),('scan_count',0),('timeline',[])]:
        st.session_state[k] = v
    st.session_state.port_hits = defaultdict(int)
    st.session_state.attack_counts = defaultdict(int)
    st.session_state.start_time = datetime.datetime.now()
    st.rerun()

# ── MAIN LAYOUT ────────────────────────────────────────────────────────────────
col_main, col_side = st.columns([3, 2])

with col_main:
    st.markdown("<div class='section-label'>Live Monitoring</div>", unsafe_allow_html=True)

    if st.button("▶  INITIATE SCAN", type="primary", use_container_width=True):
        with st.spinner(f"ECLIPSIS scanning network for {duration} seconds..."):
            results, pkt_count = run_monitoring(duration)

        threats = [r for r in results if r['prediction'] != 'BENIGN']
        if threats:
            for t in threats:
                sev, sev_class = get_severity(t['prediction'])
                st.markdown(f"""
                <div class='alert-card'>
                    <div class='attack-type'>🚨 {t['prediction'].upper()}
                        <span class='sev-{sev_class}' style='margin-left:8px;'>{sev}</span>
                    </div>
                    <div class='detail'>📍 {t['source_ip']} &nbsp;|&nbsp; Port {t['port']} &nbsp;|&nbsp; {t['confidence']:.1f}% confidence</div>
                    <div class='detail'>{'🚫 IP BLOCKED via Windows Firewall' if t['blocked'] else '⚠️ ALERT GENERATED'}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class='safe-card'>
                ✅ &nbsp; {pkt_count} packets — {len(results)} flows — network clear
            </div>""", unsafe_allow_html=True)

    # ── ATTACK TIMELINE ──────────────────────────────────────────────────────
    st.markdown("<div class='section-label' style='margin-top:1.2rem;'>Attack Timeline</div>",
                unsafe_allow_html=True)
    if st.session_state.timeline:
        timeline_html = ""
        for event in reversed(st.session_state.timeline[-15:]):
            dot_class = 'timeline-dot-threat' if event['type'] == 'threat' else 'timeline-dot-safe'
            text_class = 'timeline-text-threat' if event['type'] == 'threat' else 'timeline-text-safe'
            timeline_html += f"""
            <div class='timeline-event'>
                <span class='timeline-time'>{event['time']}</span>
                <span class='{dot_class}'></span>
                <span class='{text_class}'>{event['text']}</span>
            </div>"""
        st.markdown(timeline_html, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style='font-family:"Share Tech Mono",monospace; color:#1a3a5a;
             font-size:0.78rem; padding:1.5rem; text-align:center;
             border:1px dashed #0e2a4a; border-radius:6px;'>
            Timeline appears after first scan
        </div>""", unsafe_allow_html=True)

    # ── MONITORING LOG ───────────────────────────────────────────────────────
    st.markdown("<div class='section-label' style='margin-top:1.2rem;'>Full Monitoring Log</div>",
                unsafe_allow_html=True)
    if st.session_state.monitoring_log:
        df_log = pd.DataFrame(st.session_state.monitoring_log)
        df_log['status'] = df_log['prediction'].apply(
            lambda x: '🚨 THREAT' if x != 'BENIGN' else '✅ SAFE')
        st.dataframe(
            df_log[['timestamp','source_ip','port','prediction','confidence','severity','status']].rename(columns={
                'timestamp':'Time','source_ip':'Source IP','port':'Port',
                'prediction':'Classification','confidence':'Conf %',
                'severity':'Severity','status':'Status'
            }),
            use_container_width=True, hide_index=True
        )
    else:
        st.markdown("""
        <div style='font-family:"Share Tech Mono",monospace; color:#1a3a5a;
             font-size:0.78rem; padding:2rem; text-align:center;
             border:1px dashed #0e2a4a; border-radius:6px;'>
            No data — press INITIATE SCAN to begin
        </div>""", unsafe_allow_html=True)

with col_side:
    # ── RECENT ALERTS ────────────────────────────────────────────────────────
    st.markdown("<div class='section-label'>Recent Alerts</div>", unsafe_allow_html=True)
    if st.session_state.alerts:
        for alert in reversed(st.session_state.alerts[-4:]):
            st.markdown(f"""
            <div class='alert-card'>
                <div class='attack-type'>⚡ {alert['attack']}
                    <span class='sev-{alert["sev_class"]}' style='margin-left:6px;'>{alert['severity']}</span>
                </div>
                <div class='detail'>📍 {alert['ip']} &nbsp; 🔌 Port {alert['port']}</div>
                <div class='geo'>{alert.get('geo','🌐 Unknown')}</div>
                <div class='detail'>📊 {alert['confidence']:.1f}% &nbsp; 🕐 {alert['time']}</div>
                <div class='detail'>{'🚫 BLOCKED' if alert['blocked'] else '⚠️ FLAGGED'}</div>
            </div>""", unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class='safe-card'>✅ &nbsp; No threats detected</div>
        """, unsafe_allow_html=True)

    # ── TRAFFIC DISTRIBUTION ─────────────────────────────────────────────────
    st.markdown("<div class='section-label' style='margin-top:1rem;'>Traffic Distribution</div>",
                unsafe_allow_html=True)
    if st.session_state.monitoring_log:
        df_chart = pd.DataFrame(st.session_state.monitoring_log)
        counts = df_chart['prediction'].value_counts()
        colors = ['#00e676' if l == 'BENIGN' else '#ff4455' for l in counts.index]
        fig = go.Figure(go.Pie(
            labels=counts.index, values=counts.values,
            marker=dict(colors=colors, line=dict(color='#060d1a', width=2)),
            textfont=dict(family='Share Tech Mono', size=10, color='white'),
            hole=0.45
        ))
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(t=10,b=10,l=10,r=10), height=220,
            legend=dict(font=dict(family='Share Tech Mono',size=9,color='#7a9bb5'),
                       bgcolor='rgba(0,0,0,0)'))
        st.plotly_chart(fig, use_container_width=True)

    # ── PORT HEATMAP ─────────────────────────────────────────────────────────
    st.markdown("<div class='section-label'>Port Activity Heatmap</div>",
                unsafe_allow_html=True)
    if st.session_state.port_hits:
        port_df = pd.DataFrame(list(st.session_state.port_hits.items()),
                               columns=['Port','Hits']).sort_values('Hits', ascending=False).head(10)
        fig2 = go.Figure(go.Bar(
            x=port_df['Port'].astype(str),
            y=port_df['Hits'],
            marker=dict(
                color=port_df['Hits'],
                colorscale=[[0,'#003d5c'],[0.5,'#00a0cc'],[1,'#00d4ff']],
                showscale=False,
                line=dict(color='#060d1a', width=1)
            ),
            text=port_df['Hits'],
            textposition='outside',
            textfont=dict(family='Share Tech Mono', size=9, color='#7a9bb5')
        ))
        fig2.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(t=10,b=10,l=10,r=10), height=200,
            xaxis=dict(title='Port', tickfont=dict(family='Share Tech Mono',size=9,color='#4a7a9b'),
                      gridcolor='#0a1a2e', title_font=dict(color='#4a7a9b')),
            yaxis=dict(title='Hits', tickfont=dict(family='Share Tech Mono',size=9,color='#4a7a9b'),
                      gridcolor='#0a1a2e', title_font=dict(color='#4a7a9b'))
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.markdown("""
        <div style='font-family:"Share Tech Mono",monospace; color:#1a3a5a;
             font-size:0.75rem; padding:1rem; text-align:center;
             border:1px dashed #0e2a4a; border-radius:6px;'>
            Port data appears after first scan
        </div>""", unsafe_allow_html=True)

# ── FOOTER ─────────────────────────────────────────────────────────────────────
st.markdown("<hr class='cyber-divider'>", unsafe_allow_html=True)
st.markdown(f"""
<div class='status-line'>
ECLIPSIS &nbsp;|&nbsp; REAL-TIME NETWORK THREAT INTELLIGENCE SYSTEM &nbsp;|&nbsp;
AI MODEL: RANDOM FOREST 15-CLASS &nbsp;|&nbsp;
{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; OPERATIONAL
</div>
""", unsafe_allow_html=True)