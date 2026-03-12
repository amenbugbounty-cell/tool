
import asyncio
import aiohttp
import argparse
import time
import re
from urllib.parse import urlparse, urljoin
from typing import Set, List, Dict, Any, Optional
from vuln_engine import VulnerabilityScanner
from logger import EnhancedLogger
from aps import AdvancedPentestingSuite

class EnhancedPentestingSuite:
    def __init__(self, domain: str, threads: int = 50, timeout: int = 10, verbose: bool = False):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.logger = EnhancedLogger(domain)
        self.found_urls: Set[str] = set()
        self.scanned_urls: Set[str] = set()
        self.lock = asyncio.Lock()

    async def extract_urls_from_text(self, text: str, base_url: str) -> List[str]:
        urls = []
        # Extract links from href and src
        for link_match in re.finditer(r'(?:href|src|url)=["\'](.*?)(?:["\']| )', text):
            link = link_match.group(1)
            absolute_link = urljoin(base_url, link)
            parsed = urlparse(absolute_link)
            if parsed.netloc.endswith(self.domain):
                urls.append(absolute_link)
        
        # Extract potential API endpoints
        endpoints = re.findall(r'/(api|v1|v2|graphql)/[a-zA-Z0-9_/-]+', text)
        for ep in endpoints:
            urls.append(urljoin(base_url, ep))
            
        return list(set(urls))

    async def scan_url_for_vulns(self, scanner: VulnerabilityScanner, url: str):
        if url in self.scanned_urls:
            return
        
        async with self.lock:
            self.scanned_urls.add(url)
            
        if self.verbose:
            self.logger.log(f"Scanning URL for vulnerabilities: {url}", 'DEBUG')
            
        findings = await scanner.scan_url(url)
        for finding in findings:
            self.logger.add_vulnerability(finding)

    async def crawl_and_scan(self, session: aiohttp.ClientSession, start_url: str, scanner: VulnerabilityScanner, depth: int = 2):
        if depth == 0 or start_url in self.found_urls:
            return
        
        async with self.lock:
            self.found_urls.add(start_url)
            
        try:
            async with session.get(start_url, timeout=self.timeout, ssl=False, allow_redirects=True) as resp:
                if resp.status != 200:
                    return
                
                # Scan current URL if it has parameters
                if '?' in str(resp.url):
                    await self.scan_url_for_vulns(scanner, str(resp.url))
                
                # Extract more URLs to crawl
                content = await resp.text()
                new_urls = await self.extract_urls_from_text(content, str(resp.url))
                
                tasks = []
                for url in new_urls:
                    if url not in self.found_urls:
                        tasks.append(self.crawl_and_scan(session, url, scanner, depth - 1))
                
                if tasks:
                    await asyncio.gather(*tasks)
                    
        except Exception as e:
            if self.verbose:
                self.logger.log(f"Error crawling {start_url}: {e}", 'ERROR')

    async def run(self):
        self.logger.log(f"Starting Enhanced Pentesting Suite for {self.domain}")
        
        # Step 1: Subdomain Enumeration (using existing APS)
        self.logger.log("Phase 1: Subdomain Enumeration & Basic Probing")
        aps_scanner = AdvancedPentestingSuite(domain=self.domain, threads=self.threads, verbose=self.verbose)
        subdomain_results = await aps_scanner.run()
        
        active_subdomains = [res.subdomain for res in subdomain_results.values() if res.http_status]
        self.logger.log(f"Found {len(active_subdomains)} active subdomains with HTTP/S")

        # Step 2: Deep Vulnerability Scanning
        self.logger.log("Phase 2: Deep Vulnerability Scanning & Crawling")
        async with aiohttp.ClientSession() as session:
            scanner = VulnerabilityScanner(session, timeout=self.timeout, verbose=self.verbose)
            
            tasks = []
            for sub in active_subdomains:
                url = f"https://{sub}" # Start with HTTPS
                tasks.append(self.crawl_and_scan(session, url, scanner))
                
            if tasks:
                # Limit concurrency for crawling
                semaphore = asyncio.Semaphore(self.threads)
                async def sem_task(task):
                    async with semaphore:
                        return await task
                
                await asyncio.gather(*[sem_task(task) for task in tasks])

        self.logger.log("Scan Completed!")
        print(self.logger.get_summary())

async def main():
    parser = argparse.ArgumentParser(description="Enhanced Pentesting Suite - All-in-One Bug Bounty Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    suite = EnhancedPentestingSuite(domain=args.domain, threads=args.threads, verbose=args.verbose)
    await suite.run()

if __name__ == "__main__":
    asyncio.run(main())
