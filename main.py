# ✅ Final Single-File IoT Privacy Dashboard: All Features Combined

import streamlit as st
import pyshark
import pandas as pd
import plotly.express as px
from collections import defaultdict, Counter
import datetime, os, requests, tempfile
from fpdf import FPDF
import re

st.set_page_config(page_title="IoT Privacy Risk Dashboard", layout="wide")

CATEGORY_MAP = {
    "tracking": ["doubleclick.net", "google-analytics", "ads.twitter"],
    "content": ["youtube", "netflix", "steampowered"],
    "telemetry": ["miniupnpd", "upnp", "openwrt", "desc.xml", "metrics"],
    "firmware": ["firmware", "model", "mac"]
}
INSECURE_PROTOCOLS = ["HTTP", "SSDP", "UPNP"]
GEO_CACHE = {}

GDPR_COUNTRIES = {"Germany", "France", "Italy", "Spain", "Sweden", "Netherlands", "Denmark", "Austria", "Ireland", "Finland", "Belgium", "Poland", "Portugal", "Greece"}
FIVE_EYES = {"United States", "United Kingdom", "Canada", "Australia", "New Zealand"}

PII_PATTERNS = {
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Phone": r"\b(?:\+\d{1,3}[-.\s]?|\d{1,4}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "MAC Address": r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])",
    "IP Address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
}

ALLOWED_MAC_FIELDS = ["eth.src", "eth.dst", "eth.addr", "mac", "mac-address"]

def geoip_lookup(ip):
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
            GEO_CACHE[ip] = "Local"
        else:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=2).json()
            GEO_CACHE[ip] = resp.get("country", "Unknown")
    except:
        GEO_CACHE[ip] = "Unknown"
    return GEO_CACHE[ip]

def categorize_domain(domain):
    if not domain:
        return "unknown"
    target = domain.lower()
    for category, patterns in CATEGORY_MAP.items():
        for p in patterns:
            if p in target:
                return category
    return "unknown"

def detect_pii(headers):
    matches = []
    if not isinstance(headers, dict):
        return matches
    try:
        for label, pattern in PII_PATTERNS.items():
            for key, val in headers.items():
                if label == "MAC Address" and not any(f in key.lower() for f in ALLOWED_MAC_FIELDS):
                    continue
                found = re.findall(pattern, str(val))
                for item in found:
                    matches.append(f"{label}: {item} (in {key})")
    except Exception as e:
        matches.append(f"⚠️ Error parsing headers: {str(e)}")
    return matches

def parse_pcap(file_path):
    cap = pyshark.FileCapture(file_path, use_json=True, include_raw=False)
    results = defaultdict(Counter)
    leaks = []
    pii_leaks = []
    dnt_detected = []
    times = defaultdict(int)
    consent_violations = []
    geo_countries = []
    heatmap_data = []

    start_time = None
    for pkt in cap:
        try:
            ts = float(pkt.sniff_timestamp)
            if start_time is None:
                start_time = ts
            minute = datetime.datetime.fromtimestamp(ts).replace(second=0, microsecond=0)
            hour = datetime.datetime.fromtimestamp(ts).hour
            times[minute] += 1

            proto = pkt.highest_layer
            results['protocols'][proto] += 1
            if proto in INSECURE_PROTOCOLS:
                results['insecure'][proto] += 1
            heatmap_data.append((proto, hour))

            if hasattr(pkt, 'ip'):
                src = pkt.ip.src
                dst = pkt.ip.dst
                results['top_talkers'][src] += 1
                results['ips'][dst] += 1
                cat = categorize_domain(dst)
                results['categories'][cat] += 1
                geo = geoip_lookup(dst)
                geo_countries.append(geo)
                if ts - start_time < 5:
                    consent_violations.append(f"{src} -> {dst} at {datetime.datetime.fromtimestamp(ts)}")


            if hasattr(pkt, 'http'):
                headers = pkt.http._all_fields
                pii_matches = detect_pii(headers)
                if pii_matches:
                    pii_leaks.extend(pii_matches)
                if 'http.user_agent' in headers and 'dnt' in headers.get('http.user_agent').lower():
                    dnt_detected.append(pkt.frame_info.time)
                for k, v in headers.items():
                    if any(tag in k.lower() for tag in ["firmware", "model", "mac", "server"]):
                        leaks.append(f"{k.upper()}: {v}")
        except:
            continue
    cap.close()
    total_cat = sum(results['categories'].values())
    risk = (results['categories']['tracking'] + results['categories']['telemetry']) / max(total_cat, 1) * 100
    return dict(results), dict(times), leaks, pii_leaks, dnt_detected, geo_countries, consent_violations, heatmap_data, round(risk, 2)

# ✅ Full UI and all graphs preserved — will regenerate complete UI now with all features included

st.title("📡 IoT Privacy Risk Dashboard")
uploaded_file = st.file_uploader("Upload a .pcap or .pcapng file", type=["pcap", "pcapng"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    results, times, leaks, pii_leaks, dnt_detected, geo_countries, consent_violations, heatmap_data, risk = parse_pcap(tmp_path)
    os.remove(tmp_path)

    st.metric("🔒 Privacy Risk Score", f"{risk}%")

    st.subheader("📊 Traffic Categories")
    df_cat = pd.DataFrame(results['categories'].items(), columns=["Category", "Count"])
    st.plotly_chart(px.bar(df_cat, x="Category", y="Count", color="Category"), use_container_width=True)

    st.subheader("📦 Protocol Usage")
    df_proto = pd.DataFrame(results['protocols'].items(), columns=["Protocol", "Count"])
    st.plotly_chart(px.bar(df_proto, x="Protocol", y="Count", color="Protocol"), use_container_width=True)

    st.subheader("👥 Top Talkers")
    df_talkers = pd.DataFrame(results['top_talkers'].items(), columns=["IP", "Packets"]).nlargest(10, "Packets")
    df_talkers["Country"] = df_talkers["IP"].apply(geoip_lookup)
    st.dataframe(df_talkers)

    st.subheader("⏱️ Packets Over Time")
    df_time = pd.DataFrame(sorted(times.items()), columns=["Time", "Packets"])
    st.plotly_chart(px.line(df_time, x="Time", y="Packets", title="Traffic Rate"), use_container_width=True)

    st.subheader("🌍 Jurisdiction Mapping")
    country_df = pd.DataFrame(geo_countries, columns=["Country"])
    country_df = country_df[country_df["Country"] != "Local"]
    if not country_df.empty:
        country_df["GDPR"] = country_df["Country"].apply(lambda x: "✅" if x in GDPR_COUNTRIES else "❌")
        country_df["Five Eyes"] = country_df["Country"].apply(lambda x: "⚠️" if x in FIVE_EYES else "")
        st.dataframe(country_df.value_counts().reset_index().rename(columns={0: "Count"}))

    st.subheader("🕒 Risk Heatmap (Protocol × Hour)")
    if heatmap_data:
        df_heat = pd.DataFrame(heatmap_data, columns=["Protocol", "Hour"])
        df_heat["Count"] = 1
        df_pivot = df_heat.pivot_table(index="Protocol", columns="Hour", values="Count", aggfunc="sum", fill_value=0)
        st.plotly_chart(px.imshow(df_pivot, labels=dict(color="Packet Count")), use_container_width=True)

    st.subheader("🚨 Consent Flow Violations")
    if consent_violations:
        st.error("Data sent before user interaction (within 5 seconds):")
        for v in consent_violations:
            st.write(f"• {v}")
    else:
        st.success("No early data transmissions detected.")

    st.subheader("📄 Metadata Leaks")
    if leaks:
        for leak in leaks:
            st.error(leak)
    else:
        st.success("No critical metadata exposure found.")

    st.subheader("🕵️ PII Leaks Detected")
    if pii_leaks:
        for pii in pii_leaks:
            st.warning(pii)
    else:
        st.success("No PII (emails, phones, IPs, MACs) found in headers.")

    st.subheader("📡 Do Not Track (DNT) Headers")
    if dnt_detected:
        st.info(f"DNT header detected in {len(dnt_detected)} packet(s)")
    else:
        st.warning("No DNT headers found in HTTP requests.")

    st.subheader("📥 Generate Annotated PDF Summary")
    if st.button("Download Report"):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="IoT Privacy Dashboard Report", ln=True, align='C')
        pdf.ln()
        pdf.cell(200, 10, txt=f"Risk Score: {risk}%", ln=True)
        pdf.ln()

        def label_threat(level):
            return {"High": "[HIGH]", "Medium": "[MEDIUM]", "Low": "[LOW]"}[level]


        pdf.set_font("Arial", size=11)
        pdf.cell(200, 8, txt=f"{label_threat('High')} PII Leaks: {len(pii_leaks)}", ln=True)
        pdf.cell(200, 8, txt=f"{label_threat('Medium')} Metadata Leaks: {len(leaks)}", ln=True)
        pdf.cell(200, 8, txt=f"{label_threat('High')} Consent Violations: {len(consent_violations)}", ln=True)
        pdf.cell(200, 8, txt=f"{label_threat('Low')} DNT Headers Present: {len(dnt_detected)}", ln=True)
        pdf.ln()

        for section, items in [("PII Leak Details", pii_leaks), ("Metadata Leak Details", leaks), ("Consent Violations", consent_violations)]:
            if items:
                pdf.set_font("Arial", style="B", size=11)
                pdf.cell(200, 10, txt=section, ln=True)
                pdf.set_font("Arial", size=10)
                for item in items:
                    pdf.cell(200, 8, txt=str(item), ln=True)
                pdf.ln()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_pdf:
            pdf.output(tmp_pdf.name)
            with open(tmp_pdf.name, "rb") as f:
                st.download_button("📄 Download Report", f.read(), file_name="iot_privacy_report.pdf", mime="application/pdf")

