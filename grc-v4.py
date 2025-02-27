import os
import json
import subprocess
import time
import numpy as np
from sklearn.ensemble import RandomForestClassifier

def run_command(command, timeout=10):
    try:
        start_time = time.time()
        result = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=timeout)
        elapsed_time = time.time() - start_time
        if elapsed_time >= timeout:
            return "[SKIPPED] Command timed out."
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[SKIPPED] Command timed out."

class GRCAuditTool:
    def __init__(self):
        self.results = {
            "OS Information": self.get_os_info(),
            "Firewall Status": self.check_firewall(),
            "SSH Configuration": self.check_ssh_config(),
            "Open Ports": self.check_open_ports(),
            "Users & Permissions": self.check_users_permissions(),
            "Disk Encryption": self.check_disk_encryption(),
            "Log Integrity": self.check_log_integrity(),
            "Vulnerabilities": self.check_vulnerabilities(),
            "Exploitable Services": self.check_exploitable_services()
        }
        self.risk_scores = self.calculate_risk_scores()

    def get_os_info(self):
        return run_command("lsb_release -a 2>/dev/null || cat /etc/*release")

    def check_firewall(self):
        return run_command("sudo ufw status verbose || sudo iptables -L")

    def check_ssh_config(self):
        return run_command("grep -E 'PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config")
    
    def check_open_ports(self):
        return run_command("netstat -tulnp | grep LISTEN")

    def check_users_permissions(self):
        sudo_users = run_command("grep '^sudo:.*$' /etc/group | cut -d: -f4")
        return {"Sudo Users": sudo_users.split(",") if sudo_users else []}

    def check_disk_encryption(self):
        encryption_status = run_command("lsblk -o NAME,MOUNTPOINT,FSTYPE,TYPE,UUID,RO,RM,SIZE,MODEL | grep crypt")
        return "Encrypted" if encryption_status else "No disk encryption detected"

    def check_log_integrity(self):
        return run_command("ls -l /var/log/ | grep -E 'syslog|auth.log|secure'")
    
    def check_vulnerabilities(self):
        #Q29kZSBieSBKRUpPIEogJiBHUkVFU0hNQSBZQVNITUkK
        return run_command("sudo lynis audit system --quick | grep -i warning", timeout=20)
    
    def check_exploitable_services(self):
        open_ports = run_command("netstat -tulnp | grep LISTEN | awk '{print $4, $7}'")
        exploitable_services = []

        exploitdb_file = "exploitdb_services.txt"

        if not os.path.exists(exploitdb_file):
            return "ExploitDB services list not found. Skipping exploit check."

        with open(exploitdb_file, "r") as exploitdb:
            known_exploits = exploitdb.readlines()

        for line in open_ports.split("\n"):
            for exploit in known_exploits:
                if any(service in line for service in exploit.strip().split(",")):
                    exploitable_services.append(line)

        return exploitable_services if exploitable_services else "No known exploitable services detected"

    def calculate_risk_scores(self):
        risk_factors = {
            "Firewall Status": 3,
            "SSH Configuration": 5,
            "Open Ports": 4,
            "Disk Encryption": 4,
            "Vulnerabilities": 5,
            "Exploitable Services": 5
        }
        
        risk_scores = {}
        for key, weight in risk_factors.items():
            value = self.results.get(key, "")
            if "inactive" in value or "PermitRootLogin yes" in value or "No disk encryption detected" in value or value:
                risk_scores[key] = weight
            else:
                risk_scores[key] = 1
        
        return risk_scores

    def generate_report(self):
        vulnerabilities = []
        recommendations = []
        
        for key, risk in self.risk_scores.items():
            if risk > 2:
                vulnerabilities.append(f"{key} is at risk (Score: {risk}/5).")
                recommendations.append(f"Mitigate {key} risk by applying recommended security measures.")
        
        report_data = {
            "Vulnerabilities": vulnerabilities,
            "Recommendations": recommendations,
            "Risk Scores": self.risk_scores
        }
        
        print("\n[🔍] Audit Report:")
        for v in vulnerabilities:
            print(f" - [❌] {v}")
        
        print("\n[✅] Recommended Actions:")
        for r in recommendations:
            print(f" - {r}")
        
        with open("audit_report.json", "w") as report:
            json.dump(report_data, report, indent=4)
        
        print("\n[✔] Report saved as 'audit_report.json'")

if __name__ == "__main__":
    audit_tool = GRCAuditTool()
    audit_tool.generate_report()
    #Q29kZSBieSBKRUpPIEogJiBHUkVFU0hNQSBZQVNITUkK


#Q29kZSBieSBKRUpPIEogJiBHUkVFU0hNQSBZQVNITUkK


