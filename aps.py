
import requests
import dns.resolver
import concurrent.futures
import threading
import time
import argparse
import json
import socket
import ssl
import random
import asyncio
import aiohttp
import re
from urllib.parse import urlparse, urljoin
from typing import Set, List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from queue import Queue
from collections import deque

# Suppress InsecureRequestWarning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

@dataclass
class SubdomainResult:
    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    mx_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    soa_record: Optional[str] = None
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    response_time: float = 0.0
    has_ssl: bool = False
    ssl_issuer: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    service_banners: Dict[int, str] = field(default_factory=dict)
    http_headers: Dict[str, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    js_endpoints: List[str] = field(default_factory=list)
    sensitive_files: List[str] = field(default_factory=list)

class AdvancedPentestingSuite:
    def __init__(self, domain: str, threads: int = 50, timeout: int = 5,
                 verbose: bool = False, output: Optional[str] = None,
                 aggressive: bool = False, enable_ai: bool = False):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output = output
        self.aggressive = aggressive
        self.enable_ai = enable_ai

        self.found_subdomains: Set[str] = set()
        self.results: Dict[str, SubdomainResult] = {}
        self.lock = threading.Lock()
        self.log_file = f"aps_log_{int(time.time())}.txt"

        self.wordlists = {
            'common': ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
                      'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover',
                      'autoconfig', 'm', 'imap', 'test', 'ns', 'pop3', 'dev',
                      'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
                      'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
                      'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'vpn',
                      'staging', 'backup', 'mx1', 'crm', 'cms', 'portal', 'svn',
                      'magento', 'ajax', 'php', 't', 'events', 's', 'owa', 'bbs',
                      'phone', 'net', 'my', 'dns2', 'api', 'exchange', 'apps',
                      'download', 'forum', 'demo', 'id', 'adc', 'lc', 'en', 'git',
                      'svn', 'mba', 'air', 'v2', 'direct', 'fb', 'ads', 'click',
                      'link', 'host', 'int', 'it', 'edu', 'go', 'g', 'video', 'cc',
                      'blog', 'jpg', 'ns4', 'status', 'survey', 'w', 'ww', 'top',
                      'win', 'zip', 'pub', 'ins', 'rich', 'site', 'click', 'feed',
                      'mall', 'store', 'tech', 'fun', 'cab', 'aid', 'online', 'pro'],
            'cloud': ['aws', 'azure', 'cloud', 'digitalocean', 'heroku', 'google',
                      's3', 'ec2', 'compute', 'storage', 'blob', 'computeengine'],
            'dev': ['dev', 'stage', 'staging', 'test', 'qa', 'uat', 'sandbox',
                   'build', 'ci', 'cd', 'jenkins', 'gitlab', 'github', 'docker'],
            'corp': ['corp', 'internal', 'intranet', 'vpn', 'gw', 'gateway',
                    'firewall', 'dmz', 'proxy', 'ldap', 'ad', 'corp1', 'corp2']
        }

        self.alt_patterns = [
            '{sub}', '{sub}-web', 'web-{sub}', '{sub}1', '1-{sub}',
            '{sub}-dev', 'dev-{sub}', '{sub}-staging', 'staging-{sub}',
            '{sub}-test', 'test-{sub}', '{sub}.{sub}', '{sub}{sub}',
            'admin.{sub}', 'dev.{sub}', 'api.{sub}', 'blog.{sub}', 'cdn.{sub}'
        ]
        
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080, 8443]
        self.sensitive_files_wordlist = [
            '.git/config', '.env', 'config.inc.php', 'wp-config.php', 'configuration.php',
            'web.config', 'sitemap.xml', 'robots.txt', 'admin/', 'backup/', 'test/',
            'dump.sql', 'database.sql', '.bash_history', '.ssh/id_rsa', '.aws/credentials'
        ]

    def log(self, message: str, level: str = 'info'):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        prefix = {'info': '[*]', 'found': '[+]', 'error': '[!]', 'debug': '[-]','vuln': '[V]'}[level]
        log_entry = f"{timestamp} {prefix} {message}"
        print(log_entry)
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')

    def get_permutations(self, words: List[str]) -> List[str]:
        perms = []
        for word in words:
            for pattern in self.alt_patterns:
                perms.append(pattern.replace('{sub}', word))
        return list(set(perms + words))

    async def fetch_url(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        try:
            async with session.get(url, timeout=self.timeout, ssl=False, allow_redirects=True,
                                   headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'})
            as response:
                return await response.text()
        except aiohttp.ClientError as e:
            if self.verbose: self.log(f"Error fetching {url}: {e}", 'debug')
            return None
        except asyncio.TimeoutError:
            if self.verbose: self.log(f"Timeout fetching {url}", 'debug')
            return None

    async def fetch_crtsh(self) -> List[str]:
        """Fetch subdomains from Certificate Transparency logs"""
        subdomains = []
        try:
            url = f"https://crt.sh/?q={self.domain}&output=json"
            async with aiohttp.ClientSession() as session:
                resp_text = await self.fetch_url(session, url)
                if resp_text:
                    data = json.loads(resp_text)
                    for entry in data:
                        name = entry.get('name_value', '')
                        if name and name.endswith(self.domain):
                            subdomains.append(name.replace('*.', ''))
        except Exception as e:
            self.log(f"crt.sh error: {e}", 'error')
        return list(set(subdomains))

    async def fetch_threatcrowd(self) -> List[str]:
        """Fetch subdomains from ThreatCrowd"""
        subdomains = []
        try:
            url = f"https://www.threatcrowd.org/api/v2/domain/report?domain={self.domain}"
            async with aiohttp.ClientSession() as session:
                resp_text = await self.fetch_url(session, url)
                if resp_text:
                    data = json.loads(resp_text)
                    subdomains.extend(data.get('subdomains', []))
        except Exception as e:
            self.log(f"ThreatCrowd error: {e}", 'error')
        return subdomains

    async def fetch_alienvault(self) -> List[str]:
        """Fetch subdomains from AlienVault OTX"""
        subdomains = []
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            async with aiohttp.ClientSession() as session:
                resp_text = await self.fetch_url(session, url)
                if resp_text:
                    data = json.loads(resp_text)
                    for record in data.get('passive_dns', []):
                        hostname = record.get('hostname')
                        if hostname and hostname.endswith(self.domain):
                            subdomains.append(hostname)
        except Exception as e:
            self.log(f"AlienVault OTX error: {e}", 'error')
        return list(set(subdomains))

    async def fetch_hackertarget(self) -> List[str]:
        """Fetch subdomains from HackerTarget"""
        subdomains = []
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            async with aiohttp.ClientSession() as session:
                resp_text = await self.fetch_url(session, url)
                if resp_text:
                    for line in resp_text.splitlines():
                        parts = line.split(',')
                        if len(parts) > 0 and parts[0].endswith(self.domain):
                            subdomains.append(parts[0])
        except Exception as e:
            self.log(f"HackerTarget error: {e}", 'error')
        return list(set(subdomains))

    def ai_suggest_subs(self) -> List[str]:
        """AI-powered subdomain suggestions (simplified)"""
        if not self.enable_ai:
            return []
        suggestions = []
        try:
            from transformers import pipeline
            self.log("Loading AI model for subdomain suggestions...", 'info')
            generator = pipeline('text-generation', model='gpt2')
            prompt = f"Common subdomains for {self.domain} are: www, mail, api,"
            results = generator(prompt, max_length=50, num_return_sequences=1)
            suggested = results[0]['generated_text'].replace(prompt, "").split(",")
            suggestions = [s.strip().split(".")[0] for s in suggested if len(s.strip()) > 1]
            self.log(f"AI suggested: {suggestions}", 'info')
        except ImportError:
            self.log(" 'transformers' library not installed, skipping AI suggestions. Please install with 'pip install transformers'", 'error')
        except Exception as e:
            self.log(f"AI error: {e}", 'error')
        return suggestions

    async def check_dns(self, subdomain: str) -> Optional[SubdomainResult]:
        """Comprehensive DNS enumeration"""
        target = f"{subdomain}"
        if not target.endswith(self.domain):
            target = f"{subdomain}.{self.domain}"

        result = SubdomainResult(subdomain=target)
        start_time = time.time()

        try:
            # A and AAAA records
            try:
                ips = dns.resolver.resolve(target, 'A')
                result.ip_addresses.extend([str(ip) for ip in ips])
            except dns.resolver.NoAnswer: pass
            except dns.resolver.NXDOMAIN: return None # No such domain
            except Exception as e: self.log(f"A record error for {target}: {e}", 'debug')

            try:
                ips = dns.resolver.resolve(target, 'AAAA')
                result.ip_addresses.extend([str(ip) for ip in ips])
            except dns.resolver.NoAnswer: pass
            except dns.resolver.NXDOMAIN: return None
            except Exception as e: self.log(f"AAAA record error for {target}: {e}", 'debug')

            if not result.ip_addresses: # If no A or AAAA records, it might not be an active host
                return None

            # CNAME records
            try:
                cname = dns.resolver.resolve(target, 'CNAME')
                result.cname = str(cname[0].target).rstrip('.')
            except dns.resolver.NoAnswer: pass
            except Exception as e: self.log(f"CNAME record error for {target}: {e}", 'debug')

            # MX records
            try:
                mx = dns.resolver.resolve(target, 'MX')
                result.mx_records = [str(r.exchange).rstrip('.') for r in mx]
            except dns.resolver.NoAnswer: pass
            except Exception as e: self.log(f"MX record error for {target}: {e}", 'debug')

            # TXT records
            try:
                txt = dns.resolver.resolve(target, 'TXT')
                result.txt_records = [str(r) for r in txt]
            except dns.resolver.NoAnswer: pass
            except Exception as e: self.log(f"TXT record error for {target}: {e}", 'debug')
            
            # NS records
            try:
                ns = dns.resolver.resolve(target, 'NS')
                result.ns_records = [str(r) for r in ns]
            except dns.resolver.NoAnswer: pass
            except Exception as e: self.log(f"NS record error for {target}: {e}", 'debug')

            # SOA record
            try:
                soa = dns.resolver.resolve(target, 'SOA')
                result.soa_record = str(soa[0].mname).rstrip('.')
            except dns.resolver.NoAnswer: pass
            except Exception as e: self.log(f"SOA record error for {target}: {e}", 'debug')

            result.response_time = time.time() - start_time
            return result

        except dns.resolver.NXDOMAIN:
            return None
        except Exception as e:
            if self.verbose:
                self.log(f"DNS lookup error for {target}: {e}", 'debug')
            return None

    async def check_http(self, session: aiohttp.ClientSession, target: str, result: SubdomainResult):
        """Check if HTTP/HTTPS is available and get headers/title"""
        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{target}"
                async with session.get(url, timeout=self.timeout, ssl=False, allow_redirects=True,
                                       headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'})
                as response:
                    result.http_status = response.status
                    result.http_headers = dict(response.headers)
                    text = await response.text()
                    if '<title>' in text:
                        start = text.find('<title>') + 7
                        end = text.find('</title>')
                        if end > start:
                            result.http_title = text[start:end].strip()
                    break
            except aiohttp.ClientError as e:
                if self.verbose: self.log(f"HTTP/S error for {url}: {e}", 'debug')
                if scheme == 'https': continue # Try http if https fails
                break
            except asyncio.TimeoutError:
                if self.verbose: self.log(f"HTTP/S timeout for {url}", 'debug')
                if scheme == 'https': continue
                break
            except Exception as e:
                if self.verbose: self.log(f"Unexpected HTTP/S error for {url}: {e}", 'debug')
                if scheme == 'https': continue
                break

    async def check_ssl(self, target: str, result: SubdomainResult):
        """Check SSL certificate info"""
        try:
            context = ssl.create_default_context()
            # Disable hostname verification for initial connection, then check manually
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.open_connection(target, 443, ssl=context, happy_eyeballs_delay=0.1)
            writer.close()
            await writer.wait_closed()

            # Re-establish connection with hostname verification for cert details
            context = ssl.create_default_context()
            sock = socket.create_connection((target, 443), timeout=self.timeout)
            ssock = context.wrap_socket(sock, server_hostname=target)
            cert = ssock.getpeercert()
            ssock.close()
            sock.close()

            result.has_ssl = True
            issuer = dict(x[0] for x in cert['issuer'])
            result.ssl_issuer = issuer.get('organizationName', 'Unknown')
        except Exception as e:
            if self.verbose: self.log(f"SSL error for {target}: {e}", 'debug')

    async def port_scan(self, target_ip: str, result: SubdomainResult):
        """Asynchronous port scanner"""
        async def _scan_port(ip: str, port: int):
            try:
                reader, writer = await asyncio.open_connection(ip, port, timeout=self.timeout)
                banner = await asyncio.wait_for(reader.read(1024), timeout=1)
                writer.close()
                await writer.wait_closed()
                return port, banner.decode(errors='ignore').strip()
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None, None
            except Exception as e:
                if self.verbose: self.log(f"Port scan error for {ip}:{port}: {e}", 'debug')
                return None, None

        tasks = [_scan_port(target_ip, port) for port in self.common_ports]
        for future in asyncio.as_completed(tasks):
            port, banner = await future
            if port:
                result.open_ports.append(port)
                if banner: result.service_banners[port] = banner
        result.open_ports.sort()

    async def crawl_and_analyze_js(self, session: aiohttp.ClientSession, url: str, result: SubdomainResult):
        """Deep crawling and JavaScript analysis"""
        visited_urls = set()
        queue = deque([url])
        
        while queue and len(visited_urls) < 100: # Limit crawl depth/breadth
            current_url = queue.popleft()
            if current_url in visited_urls: continue
            visited_urls.add(current_url)

            self.log(f"Crawling: {current_url}", 'debug')
            text = await self.fetch_url(session, current_url)
            if not text: continue

            # Extract links and potential subdomains
            for link_match in re.finditer(r'(?:href|src|url)=[""](.*?)(?:""|"|
)', text):
                link = link_match.group(1)
                parsed_link = urlparse(link)
                if parsed_link.netloc and parsed_link.netloc.endswith(self.domain) and parsed_link.netloc not in self.found_subdomains:
                    # Add to candidates for DNS resolution later
                    self.log(f"Found potential subdomain in JS: {parsed_link.netloc}", 'debug')
                    with self.lock:
                        self.found_subdomains.add(parsed_link.netloc)

                if link.startswith('/') or link.startswith(url) or urlparse(link).netloc == urlparse(url).netloc:
                    absolute_link = urljoin(url, link)
                    if absolute_link not in visited_urls:
                        queue.append(absolute_link)
            
            # Analyze JavaScript for endpoints and secrets
            if current_url.endswith('.js'):
                # Simple regex for common API endpoints and sensitive strings
                endpoints = re.findall(r'/(api|v1|v2|graphql)/[a-zA-Z0-9_/-]+', text)
                result.js_endpoints.extend(list(set(endpoints)))
                
                # Look for API keys, tokens (simplified)
                if re.search(r'(api_key|token|secret|password)=[""][a-zA-Z0-9_/-]{16,}[""]', text):
                    result.vulnerabilities.append(f"Potential hardcoded secret in {current_url}")

    async def check_security_headers(self, result: SubdomainResult):
        """Check for missing security headers"""
        if not result.http_headers: return

        missing_headers = []
        security_headers = {
            'Strict-Transport-Security': 'HSTS', 'Content-Security-Policy': 'CSP',
            'X-Content-Type-Options': 'X-CTO', 'X-Frame-Options': 'XFO',
            'Referrer-Policy': 'Referrer-Policy', 'Permissions-Policy': 'Permissions-Policy'
        }

        for header, name in security_headers.items():
            if header not in result.http_headers:
                missing_headers.append(name)
        
        if missing_headers:
            result.vulnerabilities.append(f"Missing security headers: {', '.join(missing_headers)}")

    async def check_subdomain_takeover(self, result: SubdomainResult):
        """Basic subdomain takeover check"""
        if result.cname:
            # Common patterns for vulnerable CNAMEs (simplified example)
            takeover_patterns = ['ghs.google.com', '.herokudns.com', '.s3-website-.amazonaws.com']
            for pattern in takeover_patterns:
                if pattern in result.cname:
                    result.vulnerabilities.append(f"Potential subdomain takeover via CNAME: {result.cname}")
                    break

    async def check_sensitive_files(self, session: aiohttp.ClientSession, target: str, result: SubdomainResult):
        """Check for sensitive files"""
        for scheme in ['https', 'http']:
            base_url = f"{scheme}://{target}"
            for sensitive_file in self.sensitive_files_wordlist:
                url = f"{base_url}/{sensitive_file}"
                try:
                    async with session.head(url, timeout=self.timeout, ssl=False,
                                            headers={'User-Agent': 'Mozilla/5.0'})
                    as response:
                        if response.status == 200:
                            result.sensitive_files.append(url)
                            result.vulnerabilities.append(f"Found sensitive file: {url}")
                except aiohttp.ClientError: pass
                except asyncio.TimeoutError: pass
                except Exception as e:
                    if self.verbose: self.log(f"Sensitive file check error for {url}: {e}", 'debug')

    async def scan_host(self, subdomain_candidate: str):
        """Performs a full scan on a single subdomain candidate"""
        dns_result = await self.check_dns(subdomain_candidate)
        if not dns_result: return

        with self.lock:
            if dns_result.subdomain in self.results: # Already processed by another path (e.g., passive sources)
                existing_result = self.results[dns_result.subdomain]
                # Merge information if necessary, e.g., add new IPs if found
                existing_result.ip_addresses.extend(dns_result.ip_addresses)
                existing_result.ip_addresses = list(set(existing_result.ip_addresses))
                current_result = existing_result
            else:
                self.found_subdomains.add(dns_result.subdomain)
                self.results[dns_result.subdomain] = dns_result
                current_result = dns_result

        self.log(f"FOUND: {current_result.subdomain} (IPs: {', '.join(current_result.ip_addresses)})", 'found')

        # Perform active checks only if it's a new or significantly updated entry
        if current_result.http_status is None or self.aggressive:
            async with aiohttp.ClientSession() as session:
                await self.check_http(session, current_result.subdomain, current_result)
                await self.check_ssl(current_result.subdomain, current_result)
                await self.check_security_headers(current_result)
                await self.check_subdomain_takeover(current_result)
                await self.check_sensitive_files(session, current_result.subdomain, current_result)
                
                # Crawl and JS analysis for HTTP/S enabled subdomains
                if current_result.http_status:
                    await self.crawl_and_analyze_js(session, f"https://{current_result.subdomain}" if current_result.has_ssl else f"http://{current_result.subdomain}", current_result)

        # Port scan for each IP found
        for ip in current_result.ip_addresses:
            await self.port_scan(ip, current_result)

        # Log detailed findings
        if current_result.http_status:
            self.log(f"  └── HTTP: {current_result.http_status} | SSL: {current_result.has_ssl}", 'found')
        if current_result.open_ports:
            self.log(f"  └── Open Ports: {', '.join(map(str, current_result.open_ports))}", 'found')
        if current_result.vulnerabilities:
            for vuln in current_result.vulnerabilities:
                self.log(f"  └── VULN: {vuln}", 'vuln')
        if current_result.js_endpoints:
            self.log(f"  └── JS Endpoints: {', '.join(current_result.js_endpoints[:3])}{'...' if len(current_result.js_endpoints) > 3 else ''}", 'info')
        if current_result.sensitive_files:
            self.log(f"  └── Sensitive Files: {', '.join(current_result.sensitive_files[:3])}{'...' if len(current_result.sensitive_files) > 3 else ''}", 'info')

    async def run(self):
        self.log(f"Starting Advanced Pentesting Suite scan for {self.domain}...")
        self.log(f"Logging to {self.log_file}", 'info')

        all_words = set()

        # Built-in wordlists
        for wl in self.wordlists.values():
            all_words.update(wl)

        # Passive sources
        self.log("Fetching from passive sources (crt.sh, ThreatCrowd, AlienVault, HackerTarget)...", 'info')
        passive_tasks = [
            self.fetch_crtsh(),
            self.fetch_threatcrowd(),
            self.fetch_alienvault(),
            self.fetch_hackertarget()
        ]
        passive_results = await asyncio.gather(*passive_tasks)
        for res_list in passive_results:
            all_words.update([urlparse(s).hostname or s.split('.')[0] for s in res_list if s.endswith(self.domain)])
            self.found_subdomains.update([s for s in res_list if s.endswith(self.domain)])

        # AI suggestions
        ai_words = self.ai_suggest_subs()
        if ai_words:
            all_words.update(ai_words)

        # Generate permutations and add base domain
        subdomain_candidates = self.get_permutations(list(all_words))
        subdomain_candidates.append(self.domain) # Add the base domain itself
        subdomain_candidates = list(set(subdomain_candidates))

        self.log(f"Total {len(subdomain_candidates)} unique subdomain candidates to scan", 'info')

        # Filter out already found subdomains from passive sources to avoid redundant DNS lookups
        active_scan_candidates = [s for s in subdomain_candidates if s not in self.found_subdomains]
        self.log(f"Initiating active scan for {len(active_scan_candidates)} candidates...", 'info')

        # Concurrently scan all candidates
        tasks = [self.scan_host(candidate) for candidate in active_scan_candidates]
        # Add tasks for subdomains found via passive sources to ensure they are also fully scanned
        tasks.extend([self.scan_host(sub) for sub in self.found_subdomains if sub not in active_scan_candidates])

        # Limit concurrent tasks to self.threads
        await self.run_tasks_with_concurrency(tasks, self.threads)

        self.log(f"Done! Found {len(self.found_subdomains)} active subdomains.", 'info')

        if self.output:
            self.save_results()

        return self.results

    async def run_tasks_with_concurrency(self, tasks: List, concurrency_limit: int):
        semaphore = asyncio.Semaphore(concurrency_limit)

        async def sem_task(task):
            async with semaphore:
                return await task

        await asyncio.gather(*[sem_task(task) for task in tasks])

    def save_results(self):
        """Save results to JSON and Markdown"""
        if not self.output: return

        output_base = self.output.replace('.json', '').replace('.md', '')

        # Save to JSON
        json_output_path = f"{output_base}.json"
        with open(json_output_path, 'w') as f:
            json.dump([res.__dict__ for res in self.results.values()], f, indent=4)
        self.log(f"Results saved to {json_output_path}", 'info')

        # Save to Markdown
        md_output_path = f"{output_base}.md"
        with open(md_output_path, 'w') as f:
            f.write(f"# Advanced Pentesting Suite Results for {self.domain}\n\n")
            f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Total Active Subdomains Found:** {len(self.found_subdomains)}\n\n")
            
            for subdomain, data in self.results.items():
                f.write(f"## {subdomain}\n\n")
                f.write(f"- **IP Addresses:** {', '.join(data.ip_addresses) or 'N/A'}\n")
                if data.cname: f.write(f"- **CNAME:** {data.cname}\n")
                if data.mx_records: f.write(f"- **MX Records:** {', '.join(data.mx_records)}\n")
                if data.txt_records: f.write(f"- **TXT Records:** {', '.join(data.txt_records)}\n")
                if data.ns_records: f.write(f"- **NS Records:** {', '.join(data.ns_records)}\n")
                if data.soa_record: f.write(f"- **SOA Record:** {data.soa_record}\n")
                if data.http_status: f.write(f"- **HTTP Status:** {data.http_status}\n")
                if data.http_title: f.write(f"- **HTTP Title:** {data.http_title}\n")
                if data.has_ssl: f.write(f"- **SSL:** Yes (Issuer: {data.ssl_issuer})\n")
                if data.open_ports: f.write(f"- **Open Ports:** {', '.join(map(str, data.open_ports))}\n")
                if data.service_banners: 
                    f.write(f"- **Service Banners:**\n")
                    for port, banner in data.service_banners.items():
                        f.write(f"  - Port {port}: {banner}\n")
                if data.http_headers:
                    f.write(f"- **HTTP Headers:**\n")
                    for header, value in data.http_headers.items():
                        f.write(f"  - {header}: {value}\n")
                if data.js_endpoints:
                    f.write(f"- **JavaScript Endpoints:**\n")
                    for ep in data.js_endpoints:
                        f.write(f"  - {ep}\n")
                if data.sensitive_files:
                    f.write(f"- **Sensitive Files Found:**\n")
                    for sf in data.sensitive_files:
                        f.write(f"  - {sf}\n")
                if data.vulnerabilities:
                    f.write(f"- **Vulnerabilities:**\n")
                    for vuln in data.vulnerabilities:
                        f.write(f"  - {vuln}\n")
                f.write("\n---\n\n")
        self.log(f"Results saved to {md_output_path}", 'info')


async def main():
    parser = argparse.ArgumentParser(description="Advanced Pentesting Suite")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads/tasks")
    parser.add_argument("-o", "--output", help="Output file path (JSON and Markdown)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Enable aggressive scanning (e.g., more thorough HTTP probes)")
    parser.add_argument("--ai", action="store_true", help="Enable AI-powered suggestions (requires transformers library)")
    
    args = parser.parse_args()

    scanner = AdvancedPentestingSuite(
        domain=args.domain,
        threads=args.threads,
        output=args.output,
        verbose=args.verbose,
        aggressive=args.aggressive,
        enable_ai=args.ai
    )
    await scanner.run()

if __name__ == "__main__":
    asyncio.run(main())

