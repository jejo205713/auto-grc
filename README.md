# Automated Information Security Auditing Tool (GRC Tool)

## 🚀 Overview
The **Automated Information Security Auditing Tool (GRC Tool)** is a Python-based security auditing framework designed to assess system security configurations, detect vulnerabilities, and provide risk scoring using AI. The tool aligns with **ISO 27001, NIST, and SOC 2** compliance requirements.

## 🔹 Features
- **System Security Audits** (Firewall, SSH, Open Ports, Disk Encryption, Log Integrity)
- **Vulnerability Scanning** (Uses Lynis for system security assessment)
- **Exploitable Services Detection** (Matches open ports with ExploitDB threats)
- **AI-Powered Risk Scoring** (Uses machine learning to prioritize vulnerabilities)
- **Automated Recommendations** (Provides actionable security fixes)
- **JSON Report Generation** (Stores audit results for compliance tracking)

## 🛠 Installation
### **1️⃣ Install System Dependencies**
```bash
sudo apt update && sudo apt install net-tools lynis ufw -y
```

### **2️⃣ Install Python Dependencies**
```bash
pip install numpy scikit-learn pandas matplotlib seaborn
```

## 🎯 Usage
### **Run the Security Audit**
```bash
python3 grc-v4.py
```
### **Output**
![Output](https://github.com/jejo205713/auto-gcr/raw/main/Output.png)
- The tool prints **detected vulnerabilities** and **recommended fixes**.
- A detailed JSON report is saved as **`audit_report.json`**.

## 📌 Risk Scoring Methodology
The tool assigns **risk scores (1-5)** based on:
| Security Factor        | Risk Weight |
|-----------------------|-------------|
| Firewall Status       | 3           |
| SSH Configuration     | 5           |
| Open Ports           | 4           |
| Disk Encryption       | 4           |
| System Vulnerabilities | 5           |
| Exploitable Services  | 5           |

Higher scores indicate **critical security risks**.

## 📂 Project Structure
```
│── grc-tool.py       # Main security audit script
│── exploitdb_services.txt  # List of known exploitable services
│── audit_report.json  # JSON report of audit findings
│── README.md         # Project documentation
```

## 🚀 Future Enhancements
- **Deep Learning for Threat Prediction**
- **AI Chatbot for Security Assistance**
- **Integration with SIEM (Splunk, ELK)**

## 🤝 Contributing
Feel free to submit **issues, feature requests, or pull requests**!

## ⚡ License
This project is **open-source** under the **MIT License**.

---
💻 **Developed by JEJO J & GREESHMA YASHMI** | 🔥 **Automating Security Audits with AI**

