# 🛡️ Packet Sniffer & Intrusion Detection System (IDS)

An industry-style Network Monitoring and Intrusion Detection tool built using **Python and Scapy** on Kali Linux.
The system captures real-time network packets, analyzes protocol behavior, detects suspicious activities, and stores logs for forensic investigation.

---

## 🚀 Key Features

### 🔎 Real-Time Network Monitoring

* Live packet capture from selected network interface
* Multi-protocol parsing:

  * TCP
  * UDP
  * ICMP
  * DNS
* Source and destination IP tracking
* Port-level metadata extraction

### 🛡️ Intrusion Detection Capabilities

* SYN-based port scan detection
* SYN flood detection
* Suspicious traffic alerts
* Abnormal packet pattern monitoring

### 📊 Traffic Analysis

* Top active IP identification (Top Talkers)
* Protocol distribution statistics
* Behavioral insights from captured traffic

### 💾 Logging & Forensics

* Structured traffic logging
* Dedicated alert logs
* Raw packet capture (PCAP)
* Wireshark-compatible forensic files

---

## 🧠 Technology Stack

* **Language:** Python 3
* **Library:** Scapy
* **Platform:** Kali Linux
* **Tools Used:** Wireshark, Nmap

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/aman-2-5/packet-sniffer-ids.git
cd packet-sniffer-ids
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

Run with root privileges (required for packet capture):

```bash
sudo python3 sniffer.py
```

---

## 🧪 Generating Test Traffic

You can generate network activity using:

### 🌐 DNS / ICMP Traffic

```bash
ping google.com
```

### 🔍 Port Scan Test

```bash
nmap -sT 127.0.0.1
```

### 🌐 Web Traffic

```bash
curl google.com
```

---

## 📂 Project Structure

```
packet-sniffer-ids/
│
├── sniffer.py
├── README.md
├── requirements.txt
├── logs/
├── pcaps/
└── screenshots/
```

---

## 📸 Screenshots

### IDS Terminal Output

![IDS Output](https://github.com/user-attachments/assets/6c1606ba-ed15-40b0-89c8-e27572b2cfe7)


### Traffic Log File

![Traffic Log](https://github.com/user-attachments/assets/e2fa0eed-472e-4128-b07d-9425a802d9f1)


### Wireshark PCAP Analysis

![Wireshark Capture](https://github.com/user-attachments/assets/883cf501-8db1-4f53-aa58-d7880959445f)


---

## 🔐 Use Cases

* Network monitoring
* Security research
* Intrusion detection studies
* Educational demonstrations
* Packet analysis practice
* Cybersecurity portfolio project

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security testing purposes only**.
Do not use on networks without proper permission.

---

## 👨‍💻 Author

AMAN LODHA
Cybersecurity Enthusiast | Network Security 
