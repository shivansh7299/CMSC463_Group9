# CMSC463_Group9
CMSC 463 - Group 9 project ( IOT PRIVACY RISK: UNVEILING HIDDEN NETWORK ACTIVITY IN IOT DEVICES )
# IoT Privacy Risk Dashboard

A Streamlit-based interactive dashboard that uncovers hidden network activity and privacy risks in IoT devices by analyzing packet capture files (`.pcap` / `.pcapng`).  
No special installations—just upload your capture and explore.

---

## Features

- **Protocol Breakdown**  
  See counts of HTTP, DNS, SSDP, UPnP, and other protocols.

- **Top Talkers**  
  Identify the most chatty devices (by IP & inferred country).

- **Privacy Risk Score**  
  Quantifies the percentage of tracking & telemetry traffic.

- **Metadata Leak Detection**  
  Flags exposed firmware versions, MAC addresses, HTTP headers.

- **Time-Series Visualization**  
  Packets-per-minute timeline graphs.

- **Jurisdiction Mapping**  
  Geolocates destination IPs to show where your data is going.

- **Consent Flow Highlighting**  
  Marks background analytics or firmware-update requests that imply implicit consent.

- **Downloadable PDF Report**  
  Export a full session summary with charts, scores, and leak details.

---

## Repository Structure

├── main.py # Streamlit app entrypoint
├── requirements.txt # Python dependencies
├── README.md # This document


Create & activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate      # macOS / Linux
.venv\Scripts\activate         # Windows


Install dependencies

pip install --upgrade pip
pip install -r requirements.txt

Run the app

1) streamlit run main.py
2) Open the URL from your terminal (usually http://localhost:8501) in your browser.

3) Upload a .pcap / .pcapng file via the “Browse” button.

Explore:

  Protocol usage bar charts
  
  Top talkers table
  
  Privacy Risk Score gauge
  
  Timeline graphs
  
  Jurisdiction map
  
  Consent flow highlights
  
Download the PDF report using the “Download Report” button.

