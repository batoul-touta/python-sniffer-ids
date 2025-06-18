# 🛡️ Python Network Sniffer + Intrusion Detection System (IDS)

This is a simple Python-based **Packet Sniffer** and **Intrusion Detection System** (IDS). It captures live TCP/UDP/ICMP traffic, detects suspicious behavior, logs alerts, and is perfect for cybersecurity learners and network programmers.

> ⚠️ **For educational purposes only.** Don’t use it on networks without permission.

---

## 🚀 Features

- ✅ Live packet capture (TCP, UDP, ICMP)
- ✅ Detects blacklisted IPs & suspicious ports
- ✅ Basic SYN scan detection
- ✅ CLI interface using `argparse`
- ✅ Payload preview
- ✅ Logs alerts to external file

---

## 🧠 Built With

- Python 3
- `socket`, `struct`, `argparse`, `datetime`
- Raw sockets (⚠️ requires admin privileges)
- Windows OS (tested)

---

## 📦 Usage

### 1. Run as **Administrator**
Open **PowerShell** as admin.

### 2. Run the script
```bash
python sniffer.py --ip <your-ip-address> --log output.log
