
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
from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Elite TUI Imports
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

try:
    from censys.search import CensysHosts
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False

# Suppress Warnings
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
requests_present = False
try:
    import requests
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    requests_present = True
except ImportError:
    pass

# Elite Banner
BANNER = """
[bold red]█████╗ ██████╗ ███████╗    ███████╗██╗     ██╗████████╗███████╗[/bold red]
[bold red]██╔══██╗██╔══██╗██╔════╝    ██╔════╝██║     ██║╚══██╔══╝██╔════╝[/bold red]
[bold red]███████║██████╔╝███████╗    █████╗  ██║     ██║   ██║   █████╗  [/bold red]
[bold red]██╔══██║██╔═══╝ ╚════██║    ██╔══╝  ██║     ██║   ██║   ██╔══╝  [/bold red]
[bold red]██║  ██║██║     ███████║    ███████╗███████╗██║   ██║   ███████╗[/bold red]
[bold red]╚═╝  ╚═╝╚═╝     ╚══════╝    ╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝[/bold red]
[bold white]Advanced Pentesting Suite - ELITE EDITION | v2.0[/bold white]
"""

@dataclass
class EliteResult:
    target: str
    ips: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    banners: Dict[int, str] = field(default_factory=dict)
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    vulns: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    sensitive_files: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    ssl_info: Dict[str, Any] = field(default_factory=dict)

class APSEliteEngine:
    def __init__(self, domain: str, threads: int = 50, aggressive: bool = False, 
                 shodan_key: str = None, censys_id: str = None, censys_secret: str = None):
        self.domain = domain
        self.threads = threads
        self.aggressive = aggressive
        self.shodan_key = shodan_key
        self.censys_id = censys_id
        self.censys_secret = censys_secret
        
        self.console = Console()
        self.results: Dict[str, EliteResult] = {}
        self.found_subs: Set[str] = {domain}
        self.lock = asyncio.Lock()
        self.session: Optional[aiohttp.ClientSession] = None
        self.start_time = time.time()
        self.log_file = f"aps_elite_{int(time.time())}.log"
        
        # Elite Wordlists
        self.subs_wordlist = ['www', 'mail', 'api', 'dev', 'stage', 'test', 'vpn', 'corp', 'internal', 'admin', 'portal', 'git', 'jenkins', 'docker', 'db', 'sql', 'app', 'cdn', 'static', 'secure', 'remote', 'gw', 'proxy', 'backup', 'old', 'new', 'm', 'mobile', 'api-docs', 'api-test', 'beta', 'demo', 'uat', 'qa', 'prod', 'staging', 'webmail', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'whm', 'cpanel', 'autodiscover', 'autoconfig', 'crm', 'cms', 'svn', 'magento', 'ajax', 'php', 't', 'events', 's', 'owa', 'bbs', 'phone', 'net', 'my', 'dns2', 'exchange', 'apps', 'download', 'forum', 'id', 'adc', 'lc', 'en', 'git', 'v2', 'direct', 'fb', 'ads', 'click', 'link', 'host', 'int', 'it', 'edu', 'go', 'g', 'video', 'cc', 'blog', 'jpg', 'ns4', 'status', 'survey', 'w', 'ww', 'top', 'win', 'zip', 'pub', 'ins', 'rich', 'site', 'feed', 'mall', 'store', 'tech', 'fun', 'cab', 'aid', 'online', 'pro']
        
        self.sensitive_paths = [
            '.git/config', '.env', 'config.php', 'wp-config.php', 'phpinfo.php', 
            '.htaccess', '.ssh/id_rsa', '.aws/credentials', 'backup.sql', 'dump.tar.gz',
            'admin/', 'dashboard/', 'v1/api/', 'v2/api/', 'graphql/', 'actuator/health'
        ]

    def log(self, msg: str, style: str = "white"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[[bold blue]{timestamp}[/bold blue]] {msg}", style=style)
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] {msg}\n")

    async def init_session(self):
        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.threads)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout, headers={
            'User-Agent': 'Mozilla/5.0 (Elite APS Pentest Engine; v2.0)'
        })

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def fetch_passive_dns(self):
        """Elite Passive DNS Aggregation"""
        self.log(f"Initiating Passive Recon for {self.domain}...", "bold cyan")
        sources = [
            f"https://crt.sh/?q={self.domain}&output=json",
            f"https://www.threatcrowd.org/api/v2/domain/report?domain={self.domain}",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        ]
        
        async def fetch_source(url):
            try:
                async with self.session.get(url) as resp:
                    if resp.status == 200:
                        if "json" in url:
                            data = await resp.json()
                            if isinstance(data, list): # crt.sh
                                for entry in data:
                                    name = entry.get('name_value', '')
                                    for sub in name.split('\n'):
                                        if sub.endswith(self.domain):
                                            self.found_subs.add(sub.replace('*.', ''))
                            elif isinstance(data, dict): # threatcrowd
                                for sub in data.get('subdomains', []):
                                    if sub.endswith(self.domain):
                                        self.found_subs.add(sub)
                        else: # hackertarget
                            text = await resp.text()
                            for line in text.splitlines():
                                sub = line.split(',')[0]
                                if sub.endswith(self.domain):
                                    self.found_subs.add(sub)
            except:
                pass

        await asyncio.gather(*(fetch_source(url) for url in sources))
        self.log(f"Passive Recon complete. Found {len(self.found_subs)} candidates.", "bold green")

    async def resolve_sub(self, sub: str):
        """Elite DNS Resolution & Port Scanning"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # DNS Records
            ips = []
            try:
                answers = resolver.resolve(sub, 'A')
                ips = [str(rdata) for rdata in answers]
            except: pass
            
            if not ips: return

            res = EliteResult(target=sub, ips=ips)
            
            # CNAME Check (Takeover)
            try:
                cname_answer = resolver.resolve(sub, 'CNAME')
                res.cname = str(cname_answer[0].target).rstrip('.')
                if any(p in res.cname for p in ['.herokudns.com', 's3.amazonaws.com', 'ghs.google.com']):
                    res.vulns.append(f"Potential Subdomain Takeover: {res.cname}")
            except: pass

            # HTTP Probe
            for proto in ['https', 'http']:
                try:
                    url = f"{proto}://{sub}"
                    async with self.session.get(url, allow_redirects=True, timeout=5) as resp:
                        res.http_status = resp.status
                        res.headers = dict(resp.headers)
                        soup = BeautifulSoup(await resp.text(), 'html.parser')
                        res.http_title = soup.title.string.strip() if soup.title else "No Title"
                        
                        # Aggressive JS Analysis
                        scripts = soup.find_all('script', src=True)
                        for s in scripts:
                            js_url = urljoin(url, s['src'])
                            if self.domain in js_url:
                                async with self.session.get(js_url, timeout=5) as js_resp:
                                    js_content = await js_resp.text()
                                    # Look for endpoints/secrets
                                    endpoints = re.findall(r'/(?:api|v1|v2|graphql)/[a-zA-Z0-9_/-]+', js_content)
                                    res.endpoints.extend(list(set(endpoints)))
                                    if re.search(r'(?:api_key|secret|token|password)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{16,})["\']', js_content, re.I):
                                        res.vulns.append(f"Hardcoded Secret in {js_url}")
                        break
                except: continue

            # Sensitive Path Discovery
            if res.http_status:
                for path in self.sensitive_paths:
                    try:
                        check_url = f"{'https' if res.http_status else 'http'}://{sub}/{path}"
                        async with self.session.head(check_url, timeout=3) as head_resp:
                            if head_resp.status == 200:
                                res.sensitive_files.append(check_url)
                                res.vulns.append(f"Exposed Sensitive File: {path}")
                    except: pass

            # Port Scan (Common Elite Ports)
            common_ports = [21, 22, 80, 443, 3306, 8080, 8443, 27017]
            for port in common_ports:
                try:
                    conn = asyncio.open_connection(ips[0], port)
                    _, writer = await asyncio.wait_for(conn, timeout=1)
                    res.ports.append(port)
                    writer.close()
                    await writer.wait_closed()
                except: pass

            async with self.lock:
                self.results[sub] = res
                self.log(f"ELITE FIND: {sub} | IPs: {', '.join(ips)} | Status: {res.http_status or 'N/A'}", "bold yellow")

        except Exception as e:
            if self.aggressive: self.log(f"Error scanning {sub}: {str(e)}", "dim red")

    async def run_elite_scan(self):
        await self.init_session()
        
        # Phase 1: Passive Recon
        await self.fetch_passive_dns()
        
        # Phase 2: Active Brute-force (if aggressive)
        if self.aggressive:
            self.log("Aggressive Mode: Brute-forcing additional subdomains...", "bold magenta")
            for word in self.subs_wordlist:
                self.found_subs.add(f"{word}.{self.domain}")

        # Phase 3: Deep Analysis
        self.log(f"Starting Deep Analysis of {len(self.found_subs)} candidates...", "bold cyan")
        
        # Create a progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Scanning Infrastructure...", total=len(self.found_subs))
            
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
        
        table = Table(title=f"Elite Pentest Report: {self.domain}", show_header=True, header_style="bold magenta", border_style="blue")
        table.add_column("Target", style="cyan", no_wrap=True)
        table.add_column("IP Addresses", style="white")
        table.add_column("Ports", style="green")
        table.add_column("Status", style="bold yellow")
        table.add_column("Vulnerabilities", style="bold red")

        for sub, res in self.results.items():
            vulns_text = "\n".join(res.vulns) if res.vulns else "None"
            table.add_row(
                sub,
                "\n".join(res.ips),
                ", ".join(map(str, res.ports)),
                str(res.http_status or "N/A"),
                vulns_text
            )

        self.console.print(table)
        
        # Detailed Stats
        total_vulns = sum(len(res.vulns) for res in self.results.values())
        stats_panel = Panel(
            f"Total Subdomains Scanned: [bold cyan]{len(self.found_subs)}[/bold cyan]\n"
            f"Active Hosts Identified: [bold green]{len(self.results)}[/bold green]\n"
            f"Critical Vulnerabilities: [bold red]{total_vulns}[/bold red]\n"
            f"Scan Duration: [bold white]{round(time.time() - self.start_time, 2)}s[/bold white]",
            title="Scan Summary", border_style="bold green"
        )
        self.console.print(stats_panel)

async def main():
    parser = argparse.ArgumentParser(description="APS - Elite Edition")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrency limit")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Enable aggressive brute-force")
    parser.add_argument("--shodan", help="Shodan API Key")
    
    args = parser.parse_args()
    
    console = Console()
    console.print(Align.center(BANNER))
    
    engine = APSEliteEngine(
        domain=args.domain, 
        threads=args.threads, 
        aggressive=args.aggressive,
        shodan_key=args.shodan
    )
    
    try:
        await engine.run_elite_scan()
    except KeyboardInterrupt:
        console.print("\n[bold red]Terminating Scan...[/bold red]")

if __name__ == "__main__":
    asyncio.run(main())
