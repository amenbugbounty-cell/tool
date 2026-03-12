# 🚀 Advanced Pentesting Suite (APS) - The Ultimate Collection

This repository contains three progressive versions of the **Advanced Pentesting Suite (APS)**. Each version is a significant upgrade over the previous one, adding more depth, speed, and aggressive scanning capabilities.

## 📁 Repository Structure

| File | Version | Focus | Interface |
| :--- | :--- | :--- | :--- |
| `aps.py` | v1.0 (Standard) | Subdomain Discovery & DNS | Simple Console |
| `aps_elite.py` | v2.0 (Elite) | Deep Recon & TUI Dashboard | Rich Terminal UI |
| `aps_god_tier.py` | v3.0 (God-Tier) | **Full Exploitation & Vuln Scanning** | Advanced God-Mode TUI |

---

## 🛠️ How to Run (The God-Tier Experience)

To experience the full power of the suite, it is recommended to use the **God-Tier Edition** (`aps_god_tier.py`).

### 1. Prerequisites
Ensure you have Python 3.10+ installed. Install all required elite libraries:
```bash
pip3 install rich aiohttp aioconsole beautifulsoup4 dnspython shodan
```

### 2. Basic Usage
To start a standard scan on a target:
```bash
python3 aps_god_tier.py -d target.com
```

### 3. Aggressive "God-Mode" Scan
To unleash the full brute-force engine and aggressive vulnerability payloads (SQLi, XSS, LFI, SSRF):
```bash
python3 aps_god_tier.py -d target.com -a
```

### 4. High-Performance Concurrency
To increase the number of concurrent probes (e.g., 200 threads):
```bash
python3 aps_god_tier.py -d target.com -t 200 -a
```

---

## 🛡️ God-Tier Features
- **SQLi/XSS/LFI/SSRF Engine:** Automated payload injection and response analysis.
- **S3 Bucket Hunter:** Discovery and permission testing for associated cloud storage.
- **Subdomain Takeover:** Fingerprint-based verification for 70+ cloud providers.
- **Deep JS Analysis:** Extraction of hidden API endpoints and hardcoded secrets.
- **Interactive TUI:** Real-time dashboard with live vulnerability alerts.

---

## ⚖️ Legal Disclaimer
This tool is for **authorized security auditing and educational purposes only**. Use it only on targets you own or have explicit permission to test.
