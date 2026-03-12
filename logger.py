
import time
import os
import json
from typing import Dict, Any, List

class EnhancedLogger:
    def __init__(self, domain: str):
        self.domain = domain
        self.timestamp = int(time.time())
        self.log_dir = f"logs_{self.domain}_{self.timestamp}"
        os.makedirs(self.log_dir, exist_ok=True)
        
        self.main_log = os.path.join(self.log_dir, "main_scan.log")
        self.vuln_log = os.path.join(self.log_dir, "vulnerabilities.json")
        self.potential_vuln_log = os.path.join(self.log_dir, "potential_vulnerabilities.log")
        
        self.findings = []

    def log(self, message: str, level: str = 'INFO'):
        timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S')
        prefix = {
            'INFO': '[*]', 
            'FOUND': '[+]', 
            'ERROR': '[!]', 
            'DEBUG': '[-]', 
            'VULN': '[V]', 
            'POTENTIAL': '[?]'
        }.get(level, '[*]')
        
        log_entry = f"{timestamp_str} {prefix} {message}"
        print(log_entry)
        with open(self.main_log, 'a') as f:
            f.write(log_entry + '\n')

    def add_vulnerability(self, finding: Dict[str, Any]):
        self.findings.append(finding)
        confidence = finding.get('confidence', 'Low')
        
        if confidence == 'High':
            self.log(f"CONFIRMED VULNERABILITY: {finding['type']} on {finding['url']} (Param: {finding.get('parameter', 'N/A')})", 'VULN')
        else:
            self.log(f"POTENTIAL VULNERABILITY: {finding['type']} on {finding['url']} (Param: {finding.get('parameter', 'N/A')})", 'POTENTIAL')
            with open(self.potential_vuln_log, 'a') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {json.dumps(finding)}\n")

        # Update JSON findings file
        with open(self.vuln_log, 'w') as f:
            json.dump(self.findings, f, indent=4)

    def get_summary(self) -> str:
        summary = f"\n--- Scan Summary for {self.domain} ---\n"
        summary += f"Total Findings: {len(self.findings)}\n"
        
        types = {}
        for f in self.findings:
            t = f['type']
            types[t] = types.get(t, 0) + 1
            
        for t, count in types.items():
            summary += f"- {t}: {count}\n"
            
        summary += f"Logs saved in: {self.log_dir}\n"
        return summary
