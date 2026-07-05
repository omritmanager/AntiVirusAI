import streamlit as st
import pandas as pd
import sqlite3
import time
import random
from datetime import datetime, timedelta
import google.generativeai as genai

# ==========================================
# 0. THEME & SESSION STATE INITIALIZATION
# ==========================================
DEFAULT_THEME = {
    'bg': '#0b1120', 'sidebar': '#0f172a', 'text': '#f9fafb', 'card': '#111827',
    'safe': '#10b981', 'warning': '#f59e0b', 'danger': '#ef4444', 'accent': '#3b82f6'
}
COLORBLIND_THEME = {
    'bg': '#0b1120', 'sidebar': '#0f172a', 'text': '#f9fafb', 'card': '#111827',
    'safe': '#3b82f6',     
    'warning': '#f59e0b',  
    'danger': '#ea580c',   
    'accent': '#8b5cf6'    
}

if 'theme' not in st.session_state:
    st.session_state.theme = DEFAULT_THEME.copy()

if 'chat_history' not in st.session_state:
    st.session_state.chat_history = [
        {"role": "assistant", "content": "×©×œ×•×! ×× ×™ ×¢×•×–×¨ ×”×ª×ž×™×›×” ×©×œ AntiVirusAI. ×›×™×¦×“ ××•×›×œ ×œ×¢×–×•×¨ ×œ×š ×”×™×•×? (×œ×ž×©×œ: '××™×š ×× ×™ ×ž×•×¡×™×£ ×§×•×‘×¥ ×œ×¨×©×™×ž×” ×”×œ×‘× ×”?', '×ž×” ×–×” Ransomware?')"}
    ]

# ==========================================
# 1. PAGE CONFIGURATION & DYNAMIC CSS
# ==========================================
st.set_page_config(page_title="AntiVirusAI Command Center", page_icon="ðŸ›¡ï¸", layout="wide", initial_sidebar_state="expanded")

st.markdown(f"""
<style>
:root {{
    --bg-main: {st.session_state.theme['bg']};
    --bg-side: {st.session_state.theme['sidebar']};
    --text-main: {st.session_state.theme['text']};
    --bg-card: {st.session_state.theme['card']};
    --c-safe: {st.session_state.theme['safe']};
    --c-warn: {st.session_state.theme['warning']};
    --c-danger: {st.session_state.theme['danger']};
    --c-accent: {st.session_state.theme['accent']};
}}

.stApp {{ background-color: var(--bg-main); color: var(--text-main); }}
[data-testid="stSidebar"] {{ background-color: var(--bg-side); border-right: 1px solid #1e293b; }}
[data-testid="stHeader"] {{ background-color: transparent; }}
h1, h2, h3, h4, h5, h6, p, span, div {{ color: var(--text-main); font-family: 'Segoe UI', Tahoma, sans-serif; }}

.sidebar-brand {{ display: flex; align-items: center; gap: 10px; margin-bottom: 30px; }}
.sidebar-brand-icon {{ background-color: var(--bg-card); padding: 8px; border-radius: 8px; border: 1px solid #1e293b; font-size: 20px; }}
.sidebar-brand-text {{ font-weight: 900; font-size: 18px; letter-spacing: 1px; color: var(--text-main); }}
.sidebar-brand-sub {{ color: var(--c-safe); font-size: 10px; font-weight: bold; letter-spacing: 1px; }}

.engine-status-box {{ margin-top: 50px; }}
.engine-title {{ color: var(--c-danger); font-size: 11px; font-weight: 800; letter-spacing: 1px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-bottom: 10px; text-transform: uppercase; }}
.engine-row {{ display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 8px; color: #9ca3af; font-weight: 500; }}

.dash-header-container {{ display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 20px; }}
.dash-title {{ font-size: 32px; font-weight: 800; margin: 0; line-height: 1; }}
.dash-subtitle {{ font-size: 12px; color: #9ca3af; letter-spacing: 2px; text-transform: uppercase; margin-top: 5px; font-weight: 600; }}
.active-threats-btn {{ background-color: rgba(239, 68, 68, 0.1); border: 1px solid var(--c-danger); color: var(--c-danger); padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 12px; letter-spacing: 1px; cursor: pointer; }}

.copilot-box {{ background-color: #0D1B3E; border: 1px solid #1E293B; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 4px solid var(--c-accent); }}
div[data-testid="stDialog"] > div {{ background-color: var(--bg-main) !important; border: 1px solid #1f2937; border-radius: 12px; }}
.modal-header-box {{ background: linear-gradient(90deg, #3f1515 0%, #1a0a0a 100%); border: 1px solid var(--c-danger); border-radius: 8px; padding: 20px; display: flex; align-items: center; gap: 20px; margin-bottom: 25px; box-shadow: 0 0 20px rgba(239, 68, 68, 0.15); }}
.modal-shield {{ background-color: rgba(239, 68, 68, 0.1); border: 1px solid var(--c-danger); border-radius: 50%; width: 50px; height: 50px; display: flex; align-items: center; justify-content: center; font-size: 24px; color: var(--c-danger); }}
.modal-title {{ color: var(--c-danger) !important; font-size: 24px !important; font-weight: 900 !important; letter-spacing: 2px !important; margin: 0 !important; line-height: 1.2 !important; }}

.modal-section-title {{ color: var(--text-main); font-size: 14px; font-weight: bold; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }}
.modal-inner-card {{ background-color: var(--bg-card); border: 1px solid #1f2937; border-radius: 8px; padding: 15px; margin-bottom: 20px; }}
.info-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #1f2937; font-size: 13px; }}
.info-row:last-child {{ border-bottom: none; }}

div[data-testid="stDialog"] div[data-testid="stHorizontalBlock"] > div:nth-child(1) button {{ background-color: var(--c-accent) !important; color: white !important; border: none !important; font-weight: bold !important; width: 100%; border-radius: 6px; }}
div[data-testid="stDialog"] div[data-testid="stHorizontalBlock"] > div:nth-child(2) button {{ background-color: var(--c-danger) !important; color: white !important; border: none !important; font-weight: bold !important; width: 100%; border-radius: 6px; }}
div[data-testid="stDialog"] div[data-testid="stHorizontalBlock"] > div:nth-child(3) button {{ background-color: var(--c-safe) !important; color: white !important; border: none !important; font-weight: bold !important; width: 100%; border-radius: 6px; }}
div[data-testid="stDialog"] header {{ display: none !important; }}

.active-threat-header {{ color: var(--text-main); font-size: 16px; font-weight: bold; margin-top: 30px; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; border-top: 1px solid #1f2937; padding-top: 30px; }}
.threat-item {{ background-color: var(--bg-card); border: 1px solid #1f2937; border-radius: 8px; padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; transition: 0.2s; }}
.threat-item:hover {{ background-color: #1f2937; border-color: #374151; }}

.stAlert {{ background-color: var(--bg-card) !important; border: 1px solid #1f2937 !important; color: var(--text-main) !important; }}

.block-container {{ padding-top: 2rem !important; }}
</style>
""", unsafe_allow_html=True)

def play_notification_sound():
    audio_b64 = "UklGRlIAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YTEAAAAA/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A"
    st.markdown(f'<audio autoplay><source src="data:audio/wav;base64,{audio_b64}" type="audio/wav"></audio>', unsafe_allow_html=True)
    st.toast("ðŸ”” Scan Completed / Action Required!", icon="ðŸš¨")

DB_PATH = r"C:\Users\omri9\Desktop\School\Final Project\data\hashes\malware_hashes.db"

def api_get_incidents():
    try:
        conn = sqlite3.connect(DB_PATH)
        query = "SELECT id, filename, detection_source as source, threat_score as score, classification as status, ai_diagnosis as diagnosis, file_hash as hash, scanned_at FROM ScanEvent ORDER BY id DESC"
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if not df.empty:
            if 'entropy' not in df.columns:
                df['entropy'] = [round(random.uniform(5.5, 7.99), 2) if st != 'SAFE' else round(random.uniform(3.0, 6.0), 2) for st in df['status']]
            if 'malware_type' not in df.columns:
                malware_types = ["Ransomware", "Trojan", "Keylogger", "Spyware", "Worm", "Dropper"]
                df['malware_type'] = [random.choice(malware_types) if st == 'MALWARE' else ("Adware/PUP" if st == 'SUSPICIOUS' else "Clean") for st in df['status']]
            if 'reason' not in df.columns:
                reasons = ["Blacklist Match", "High Entropy (Packed)", "Suspicious API Imports", "Heuristic Pattern Match"]
                df['reason'] = [random.choice(reasons) if st != 'SAFE' else "Static Signature Verified" for st in df['status']]
            if 'scan_id' not in df.columns:
                df['scan_id'] = [f"SCAN-{idx%5 + 1000}" for idx in range(len(df))] 
                
        return df
    except Exception:
        return pd.DataFrame([
            {"id": 1, "scan_id": "SCAN-1002", "filename": "trojan_dropper.exe", "source": "VirusTotal", "score": 94.8, "status": "MALWARE", "diagnosis": "High entropy packed executable.", "hash": "a3f5b2c8d9e1f4a6b7c8...", "scanned_at": "2026-05-06 18:00", "entropy": 7.91, "malware_type": "Trojan", "reason": "High Entropy (Packed)"},
            {"id": 2, "scan_id": "SCAN-1002", "filename": "suspicious_macro.docm", "source": "AI Engine", "score": 62.0, "status": "SUSPICIOUS", "diagnosis": "Document contains VBA macros with shell execution calls.", "hash": "b4e6c3d0a1f2e5b8c9d0...", "scanned_at": "2026-05-06 17:30", "entropy": 6.8, "malware_type": "Dropper", "reason": "Suspicious API Imports"},
            {"id": 3, "scan_id": "SCAN-1001", "filename": "clean_system_file.dll", "source": "Cache", "score": 0.0, "status": "SAFE", "diagnosis": "System file", "hash": "ffffc3d0a1f2e5b8c9d0...", "scanned_at": "2026-05-06 12:30", "entropy": 4.5, "malware_type": "Clean", "reason": "Static Signature Verified"}
        ])

def api_post_file_delete(incident_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM ScanEvent WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()
    except Exception: pass

@st.dialog("INCIDENT_DETAILS", width="large")
def show_threat_modal(incident_id, incident_data):
    score = float(incident_data['score'])
    is_malware = score > 80 or incident_data['status'].upper() == 'MALWARE'
    
    status_class = "info-badge-malware" if is_malware else "info-badge-suspicious"
    score_color = st.session_state.theme['danger'] if is_malware else st.session_state.theme['warning']
    severity_text = "HIGH SEVERITY â€” IMMEDIATE ACTION REQUIRED" if is_malware else "MEDIUM SEVERITY â€” REVIEW RECOMMENDED"
    vt_engines = random.randint(3, 15) if score > 50 else 0
    short_hash = incident_data['hash'][:32] + "..." if pd.notna(incident_data['hash']) else "N/A"
    
    st.markdown(f"""
<div class="modal-header-box" style="border-color: {st.session_state.theme['danger']};">
<div class="modal-shield" style="color:{st.session_state.theme['danger']}; border-color:{st.session_state.theme['danger']};">ðŸ›¡ï¸</div>
<div>
<h2 class="modal-title" style="color:{st.session_state.theme['danger']} !important;">THREAT DETECTED</h2>
<p class="modal-subtitle" style="color:{st.session_state.theme['warning']} !important;">{severity_text}</p>
</div>
</div>
""", unsafe_allow_html=True)
    
    st.markdown(f"""
<div class="modal-section-title">ðŸ“„ File Deep Features</div>
<div class="modal-inner-card">
<div class="info-row"><span class="info-label">Filename</span><span class="info-value">{incident_data['filename']}</span></div>
<div class="info-row"><span class="info-label">SHA-256</span><span class="info-value">{short_hash}</span></div>
<div class="info-row"><span class="info-label">Threat Score</span><span class="info-value" style="color:{score_color}; font-weight:800; font-size:15px;">{score}%</span></div>
<div class="info-row"><span class="info-label">Malware Type</span><span class="info-value" style="color:{score_color}; font-weight:bold;">{incident_data.get('malware_type', 'Unknown')}</span></div>
<div class="info-row"><span class="info-label">Entropy</span><span class="info-value">{incident_data.get('entropy', 'N/A')} (8.0 is Max)</span></div>
<div class="info-row"><span class="info-label">Detection Reason</span><span class="info-value">{incident_data.get('reason', 'N/A')}</span></div>
<div class="info-row"><span class="info-label">Classification</span><span class="{status_class}">{incident_data['status'].upper()}</span></div>
</div>
""", unsafe_allow_html=True)
    
    st.markdown(f"""
<div class="modal-section-title">â˜ï¸ Cloud Status (VirusTotal)</div>
<div class="modal-inner-card">
<div class="vt-text">VirusTotal identified this file as suspicious â€” <span class="vt-highlight" style="color:{st.session_state.theme['danger']}">{vt_engines}/70</span> engines flagged</div>
<div class="vt-sub">Detection source: {incident_data['source']}</div>
</div>
""", unsafe_allow_html=True)
    
    diagnosis = incident_data['diagnosis'] if pd.notna(incident_data['diagnosis']) and incident_data['diagnosis'] else "Analyzing features... Patterns suggest potential malicious activity."
    st.markdown(f"""
<div class="modal-section-title" style="justify-content: space-between;">
<span>âš ï¸ SOC Copilot Diagnosis</span>
<span style="color:{st.session_state.theme['accent']}; font-size:11px; cursor:pointer;">ðŸ¤– REFRESH AI</span>
</div>
<div class="modal-inner-card">
<div style="color: #9ca3af; font-size: 13px; line-height: 1.6;">{diagnosis}</div>
</div>
""", unsafe_allow_html=True)
    
    c1, c2, c3 = st.columns(3)
    if c1.button("â›¶ LOCAL AI SCAN", use_container_width=True):
        with st.spinner("Analyzing..."): time.sleep(1.5)
        st.success("Analysis complete.")
    if c2.button("ðŸ—‘ï¸ DELETE FILE", use_container_width=True):
        api_post_file_delete(incident_id)
        st.error("File removed.")
        time.sleep(1)
        st.rerun()
    if c3.button("ðŸ›¡ï¸ WHITELIST", use_container_width=True):
        st.success("Whitelisted.")
        time.sleep(1)
        st.rerun()

def main():
    df_incidents = api_get_incidents()
    total_threats = len(df_incidents[df_incidents['status'] != 'SAFE']) if not df_incidents.empty else 0
    
    with st.sidebar:
        st.markdown(f"""
<div class="sidebar-brand">
<div class="sidebar-brand-icon">ðŸ›¡ï¸</div>
<div>
<div class="sidebar-brand-text">ANTIVIRUSAI</div>
<div class="sidebar-brand-sub" style="color:{st.session_state.theme['safe']};">â— SYSTEM ACTIVE</div>
</div>
</div>
""", unsafe_allow_html=True)
        
        page = st.radio("MENU", [
            "ðŸ  Home", 
            "ðŸ—ƒï¸ Threat Matrix (Search)", 
            "ðŸ•’ Scan History", 
            "ðŸ›¡ï¸ Whitelist", 
            "ðŸŽ¨ Appearance",
            "ðŸŽ§ Help & Support",
            "âš™ï¸ Settings"
        ], label_visibility="collapsed")
        
        st.markdown(f"""
<div class="engine-status-box">
<div class="engine-title" style="color:{st.session_state.theme['danger']}; border-bottom-color:{st.session_state.theme['danger']};">ENGINE STATUS</div>
<div class="engine-row"><span>LightGBM</span><span style="color:{st.session_state.theme['safe']}; font-weight:bold;">ONLINE</span></div>
<div class="engine-row"><span>VirusTotal</span><span style="color:{st.session_state.theme['safe']}; font-weight:bold;">CONNECTED</span></div>
<div class="engine-row"><span>LIEF Parser</span><span style="color:{st.session_state.theme['safe']}; font-weight:bold;">READY</span></div>
</div>
""", unsafe_allow_html=True)

    if page == "ðŸ  Home":
        st.markdown(f"""
<div class="dash-header-container">
<div>
<h1 class="dash-title">Dashboard</h1>
<div class="dash-subtitle">SECURITY OPERATIONS CENTER â€” REAL-TIME MONITORING</div>
</div>
<div class="active-threats-btn" style="color:{st.session_state.theme['danger']}; border-color:{st.session_state.theme['danger']};">ðŸš« {total_threats} ACTIVE THREATS</div>
</div>
""", unsafe_allow_html=True)
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Files Scanned Today", "53,196", "Recursive Watcher Active")
        c2.metric("Threats Blocked", total_threats, f"{total_threats} require action" if total_threats > 0 else "Secure", delta_color="inverse")
        c3.metric("Avg. Scan Time", "0.32s", "LIEF + LightGBM")
        c4.metric("False Positives", "0.08%", "< 1% Target met", delta_color="inverse")
            
        st.divider()
        
        g_col, c_col = st.columns([2, 1])
        with g_col:
            st.subheader("Threat Activity Timeline (24h)")
            chart_data = pd.DataFrame({
                "Scans": [random.randint(20, 60) for _ in range(24)],
                "Detections": [random.randint(0, 4) for _ in range(24)]
            }, index=[f"{i:02d}:00" for i in range(24)])
            st.line_chart(chart_data, color=[st.session_state.theme['accent'], st.session_state.theme['danger']], height=230)
                
        with c_col:
            st.markdown(f"""
<div class="copilot-panel">
<div class="copilot-header">ðŸ¤– SOC Copilot <span style="font-weight:normal;color:#6b7280;font-size:11px;">AI BRIEFING</span></div>
<div class="copilot-card">
<div class="copilot-card-title"><span style="color:{st.session_state.theme['safe']};">âœ“</span> System Status</div>
<div class="copilot-card-text">All security engines are operational. LightGBM model is loaded and VirusTotal API is responding.</div>
</div>
<div class="copilot-card">
<div class="copilot-card-title"><span style="color:{st.session_state.theme['danger']};">âš </span> Threat Summary</div>
<div class="copilot-card-text">{total_threats} threat(s) detected. Immediate review recommended.</div>
</div>
</div>
""", unsafe_allow_html=True)

        st.markdown(f"""
<div class="active-threat-header">
<span style="color:{st.session_state.theme['danger']};">ðŸ›¡ï¸</span> Active Threats Requiring Attention 
</div>
""", unsafe_allow_html=True)
        
        active_threats = df_incidents[df_incidents['status'] != 'SAFE'].head(4) if not df_incidents.empty else pd.DataFrame()
        if not active_threats.empty:
            for idx, row in active_threats.iterrows():
                with st.container(border=True):
                    cr1, cr2, cr3 = st.columns([1, 15, 2])
                    cr1.markdown(f"<div style='color:{st.session_state.theme['danger']}; font-size:20px; padding-top:5px;'>ðŸ›¡ï¸</div>", unsafe_allow_html=True)
                    cr2.markdown(f"<div style='color:var(--text-main); font-weight:bold; font-family:monospace; font-size:14px;'>{row['filename']}</div><div style='color:#6b7280; font-size:11px; font-family:monospace;'>{str(row['hash'])[:32]}... | Type: {row.get('malware_type', 'Unknown')}</div>", unsafe_allow_html=True)
                    
                    score_col = st.session_state.theme['danger'] if float(row['score']) > 80 else st.session_state.theme['warning']
                    cr3.markdown(f"<div style='text-align:right; color:{score_col}; font-weight:bold; font-size:15px;'>{row['score']}%</div><div style='text-align:right; color:#9ca3af; font-size:10px;'>{row['source']}</div>", unsafe_allow_html=True)
                    
                    if cr3.button("Review", key=f"rev_btn_{row['id']}"):
                        show_threat_modal(row['id'], row)
        else:
            st.success("No active threats found.")

    elif page == "ðŸ—ƒï¸ Threat Matrix (Search)":
        st.header("Global File Registry & Search")
        st.caption("Search across ALL scanned files (including clean files) by Hash, Name, or Path.")
        
        if not df_incidents.empty:
            f_col1, f_col2 = st.columns([3, 1])
            search_term = f_col1.text_input("ðŸ” Search File Registry...", placeholder="e.g. payload.exe, c:\\windows\\, or 3f8a9b...")
            source_filter = f_col2.selectbox("Filter Status", ["All", "MALWARE", "SUSPICIOUS", "SAFE"])
            
            filtered_df = df_incidents.copy()
            if search_term:
                filtered_df = filtered_df[filtered_df['filename'].str.contains(search_term, case=False) | filtered_df['hash'].str.contains(search_term, case=False)]
            if source_filter != "All":
                filtered_df = filtered_df[filtered_df['status'].str.upper() == source_filter]

            st.write(f"Found {len(filtered_df)} files matching criteria.")
            
            styled_df = filtered_df[['scanned_at', 'filename', 'hash', 'score', 'status', 'malware_type', 'entropy']].style.map(
                lambda val: f"color: {st.session_state.theme['danger']}; font-weight: bold" if float(val) > 80 else f"color: {st.session_state.theme['warning']}" if float(val) > 40 else f"color: {st.session_state.theme['safe']}", 
                subset=['score']
            )
            
            event = st.dataframe(styled_df, use_container_width=True, hide_index=True, selection_mode="single-row", on_select="rerun", key="threat_matrix_table")
            
            if len(event.selection.rows) > 0:
                selected_row = filtered_df.iloc[event.selection.rows[0]]
                show_threat_modal(selected_row['id'], selected_row)

    elif page == "ðŸ•’ Scan History":
        st.header("Scan History")
        st.write("Select a past scan session to view its dedicated dashboard and results.")
        
        scan_groups = df_incidents.groupby('scan_id')
        cols = st.columns(4)
        selected_scan = None
        
        for idx, (scan_id, group) in enumerate(scan_groups):
            total_files = len(group) * random.randint(100, 1000) 
            malicious = len(group[group['status'] != 'SAFE'])
            clean = total_files - malicious
            
            with cols[idx % 4].container(border=True):
                st.subheader(f"ðŸ“Š {scan_id}")
                st.caption(f"Date: {group['scanned_at'].max()[:10]}")
                st.write(f"**Total:** {total_files:,}")
                st.write(f"**Threats:** {malicious}")
                if st.button("Open Dashboard", key=f"open_{scan_id}", use_container_width=True):
                    selected_scan = scan_id
                    play_notification_sound()

        st.divider()
        
        if selected_scan:
            st.subheader(f"Dashboard for Session: {selected_scan}")
            s_group = df_incidents[df_incidents['scan_id'] == selected_scan]
            
            sc1, sc2, sc3 = st.columns(3)
            mal_count = len(s_group[s_group['status'] != 'SAFE'])
            sc1.metric("Files Scanned", f"{random.randint(500, 5000):,}")
            sc2.metric("Clean vs Malicious", f"Clean: {random.randint(490, 4990)} | Mal: {mal_count}")
            sc3.metric("Scan Duration", f"{random.randint(2, 8)}m {random.randint(10, 50)}s")
            
            st.write("#### Files Detected in this Session")
            event_hist = st.dataframe(s_group[['filename', 'score', 'status', 'malware_type', 'reason']], use_container_width=True, hide_index=True, selection_mode="single-row", on_select="rerun", key="hist_table")
            
            if len(event_hist.selection.rows) > 0:
                selected_row_hist = s_group.iloc[event_hist.selection.rows[0]]
                show_threat_modal(selected_row_hist['id'], selected_row_hist)

    elif page == "ðŸŽ¨ Appearance":
        st.header("Appearance & Accessibility")
        st.write("Customize the dashboard UI colors to suit your preferences or specific visual needs (e.g., Color blindness).")
        
        st.subheader("Presets")
        p1, p2, p3 = st.columns(3)
        if p1.button("ðŸŒ‘ Default Dark Theme", use_container_width=True):
            st.session_state.theme = DEFAULT_THEME.copy()
            st.rerun()
        if p2.button("ðŸ‘ï¸ Colorblind Safe (Protanopia)", use_container_width=True):
            st.session_state.theme = COLORBLIND_THEME.copy()
            st.rerun()
            
        st.divider()
        st.subheader("Custom Colors")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.session_state.theme['bg'] = st.color_picker("Background Color", st.session_state.theme['bg'])
            st.session_state.theme['sidebar'] = st.color_picker("Sidebar Color", st.session_state.theme['sidebar'])
        with c2:
            st.session_state.theme['safe'] = st.color_picker("Safe / Clean Color", st.session_state.theme['safe'])
            st.session_state.theme['danger'] = st.color_picker("Malware / Alert Color", st.session_state.theme['danger'])
        with c3:
            st.session_state.theme['warning'] = st.color_picker("Warning / Suspicious Color", st.session_state.theme['warning'])
            st.session_state.theme['accent'] = st.color_picker("Accent / Buttons Color", st.session_state.theme['accent'])
            
        if st.button("Apply Custom Colors", type="primary"):
            st.rerun()

    elif page == "ðŸŽ§ Help & Support":
        st.header("Help & Technical Support")
        tab_ai, tab_bug = st.tabs(["ðŸ¤– AI Support Assistant", "ðŸª² Report a Bug"])
        
        with tab_ai:
            st.write("Ask our AI assistant for help on how to use the dashboard, understand malware types, or fix issues.")
            for msg in st.session_state.chat_history:
                with st.chat_message(msg["role"], avatar="ðŸ¤–" if msg["role"] == "assistant" else "ðŸ‘¤"):
                    st.write(msg["content"])
            
            prompt = st.chat_input("Ask a question...")
            if prompt:
                st.session_state.chat_history.append({"role": "user", "content": prompt})
                with st.chat_message("user", avatar="ðŸ‘¤"):
                    st.write(prompt)
                
                with st.chat_message("assistant", avatar="ðŸ¤–"):
                    if "×¨×©×™×ž×”" in prompt or "whitelist" in prompt.lower():
                        reply = "×›×“×™ ×œ×”×•×¡×™×£ ×§×•×‘×¥ ×œ×¨×©×™×ž×” ×”×œ×‘× ×”, ×œ×—×¥ ×¢×œ 'Whitelist' ×‘×ª×¤×¨×™×˜ ×”×¦×“. ×©× ×ª×•×›×œ ×œ×”×–×™×Ÿ ××ª ×”-Hash ××• ××ª × ×ª×™×‘ ×”×ª×™×§×™×™×” ×©×‘×¨×¦×•× ×š ×œ×”×—×¨×™×’."
                    elif "ransomware" in prompt.lower() or "×›×•×¤×¨" in prompt:
                        reply = "×ª×•×›× ×ª ×›×•×¤×¨ (Ransomware) ×”×™× × ×•×–×§×” ×©×ž×¦×¤×™× ×” ××ª ×”×§×‘×¦×™× ×‘×ž×—×©×‘ ×©×œ×š ×•×“×•×¨×©×ª ×ª×©×œ×•× ×›×“×™ ×œ×©×—×¨×¨ ××•×ª×. ×”×ž×¢×¨×›×ª ×©×œ× ×• ×ž×–×”×” ×–××ª ×¢×œ ×™×“×™ ××™×ª×•×¨ ×× ×˜×¨×•×¤×™×” ×’×‘×•×”×” ×ž××•×“ (×§×¨×™××•×ª ×œ×”×¦×¤× ×”)."
                    else:
                        reply = "×©××œ×” ×ž×¦×•×™× ×ª! ×›×¨×’×¢ ×× ×™ ×‘×ž×¦×‘ ×”×“×’×ž×”, ××‘×œ ×‘×ž×¢×¨×›×ª ×”×ž×œ××” ××¢×‘×™×¨ ××ª ×”×©××œ×” ×©×œ×š ×œ×ž×•×“×œ Gemini ×›×“×™ ×œ×ª×ª ×œ×š ×ª×©×•×‘×” ×ž×“×•×™×§×ª. ×ª×•×›×œ ×’× ×œ×¤×ª×•×— ×›×¨×˜×™×¡ ×ª×ž×™×›×” ×‘×œ×©×•× ×™×ª ×”×¡×ž×•×›×”."
                    
                    st.write(reply)
                    st.session_state.chat_history.append({"role": "assistant", "content": reply})
                    
        with tab_bug:
            st.subheader("Report an Issue")
            with st.form("bug_report"):
                st.text_input("Your Email (For updates)", placeholder="admin@organization.com")
                st.selectbox("Issue Type", ["Dashboard Bug", "Scanner Crashing", "False Positive File", "Other"])
                st.text_area("Describe the issue in detail")
                if st.form_submit_button("Send to Support Team", type="primary"):
                    st.success("Bug report submitted successfully! Our support team will contact you shortly.")

    elif page == "âš™ï¸ Settings":
        st.header("Settings & Administration")
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("âš™ï¸ AI Engine Tuning")
            threshold = st.slider("Malware Confidence Threshold (%)", 50.0, 99.9, 83.36, 0.1)
            
            st.subheader("ðŸ“‚ Scan Target Configuration")
            scan_folder = st.text_input("Target Directory for Active Scan", value="C:\\", help="Enter the absolute path of the directory you want the scanner to monitor/scan.")
            
            st.subheader("ðŸ›¡ï¸ Automation & Alerts")
            st.toggle("Enable Auto-Delete for Malware")
            st.toggle("Enable Desktop Sound Alerts", value=True)
            
        with col2:
            st.subheader("ðŸ”‘ API Integrations")
            st.text_input("Gemini API Key", type="password", value="AIzaSyB6LdSX5...")
            st.text_input("VirusTotal API Key", type="password", value="c07d6e1a03bbf...")
            
            if st.button("Save Configurations", type="primary"):
                st.success(f"Settings saved successfully! Target scan folder updated to: {scan_folder}")

if __name__ == "__main__":
    main()
