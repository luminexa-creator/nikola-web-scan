#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 NIKOLA SCANER  v5.0  --  Hardened Web Security & Attack Surface Auditor
================================================================================
 Author : NIKOLA TESLA
 Country: Tanzania
 Email  : hacklab01001@gmail.com
================================================================================
"""

import sys
import os
import re
import json
import ssl
import socket
import hashlib
import fnmatch
import time
import random
import subprocess
import shutil
import webbrowser
import platform
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[-] Install: pip install requests beautifulsoup4")
    sys.exit(1)

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


# ============================================================
# COLORS
# ============================================================
class C:
    G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; B = "\033[94m"
    CY = "\033[96m"; M = "\033[95m"; W = "\033[0m"; BOLD = "\033[1m"
    DIM = "\033[2m"; IT = "\033[3m"


def now_utc():
    return datetime.now(timezone.utc)


def clear():
    os.system("cls" if os.name == "nt" else "clear")


# ============================================================
# SMALL BANNER
# ============================================================
BANNER = f"""{C.CY}{C.BOLD}
  ┌──────────────────────────────────────────────┐
  │      ⚔  N I K O L A   S C A N E R  ⚔         │
  │           v5.0  ·  Web Security              │
  └──────────────────────────────────────────────┘{C.W}
"""


# ============================================================
# CONFIG
# ============================================================
CONFIG = {
    "scan": {
        "timeout": 20,
        "connect_timeout": 10,
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ),
        "alt_user_agents": [
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/121.0 Mobile Safari/537.36",
        ],
        "follow_redirects": True,
        "verify_ssl": False,
        "rate_limit": 0.20,
        "max_links": 80,
        "max_extra_checks": 14,
        "retry_attempts": 5,
        "retry_backoff": [0.8, 1.5, 2.5, 4.0, 6.0],
        "deception_mode": True,
        "military_mode": True,
    },
    "reporting": {"output_dir": "reports"},
    "evidence": {"output_dir": "evidence", "max_body_size": 20000},
    "history_file": "reports/history.json",
    "blocked_domains": ["*.gov", "*.mil", "*.bank", "*.police"],
    "author": {
        "name": "NIKOLA TESLA",
        "country": "Tanzania 🇹🇿",
        "email": "hacklab01001@gmail.com",
        "tool": "NIKOLA SCANER",
        "version": "5.0",
    },
}


# ============================================================
# SCOPE
# ============================================================
class ScopeError(Exception):
    pass


class ScopeManager:
    def __init__(self, config):
        self.blocked = config["blocked_domains"]
        self.allowed_host = None

    def set_target(self, url):
        self.allowed_host = urlparse(url).hostname

    def _matches(self, host, patterns):
        for p in patterns:
            if fnmatch.fnmatch(host, p) or host == p:
                return True
        return False

    def validate(self, url):
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            raise ScopeError(f"Invalid URL: {url}")
        if self._matches(host, self.blocked):
            raise ScopeError(f"{host} is blocked (gov/mil/bank/police).")
        if self.allowed_host and host != self.allowed_host:
            raise ScopeError(f"{host} is out-of-scope (target is {self.allowed_host})")
        return True


# ============================================================
# EVIDENCE
# ============================================================
class EvidenceCollector:
    PII_PATTERNS = [
        (r"[\w\.-]+@[\w\.-]+\.\w+", "[EMAIL_REDACTED]"),
        (r"\b\d{16}\b", "[CARD_REDACTED]"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN_REDACTED]"),
        (r"(?i)(password|passwd|pwd)\s*[:=]\s*([^\s\"'<>]+)", r"\1=[REDACTED]"),
        (r"(?i)(token|api[_-]?key|secret|bearer)\s*[:=]\s*([^\s\"'<>]+)", r"\1=[REDACTED]"),
        (r"eyJ[\w-]+\.[\w-]+\.[\w-]+", "[JWT_REDACTED]"),
    ]

    def __init__(self, config):
        self.dir = config["evidence"]["output_dir"]
        self.max_size = config["evidence"]["max_body_size"]
        os.makedirs(self.dir, exist_ok=True)
        self.files = []

    def sanitize(self, text):
        if not text:
            return ""
        for pat, repl in self.PII_PATTERNS:
            text = re.sub(pat, repl, text)
        return text

    def save(self, url, response=None, extra=None, kind="http"):
        h = hashlib.sha256((url + str(time.time()) + str(random.random())).encode()).hexdigest()[:10]
        fname = f"{self.dir}/{kind}_{h}_{int(time.time())}.txt"
        try:
            with open(fname, "w", encoding="utf-8", errors="ignore") as f:
                f.write(f"URL: {url}\n")
                f.write(f"Time: {now_utc().isoformat()}\n")
                if response is not None:
                    f.write(f"Status: {getattr(response, 'status_code', 'N/A')}\n")
                    try:
                        f.write(f"Headers:\n{json.dumps(dict(response.headers), indent=2)}\n")
                    except Exception:
                        pass
                    text = getattr(response, "text", "") or ""
                    if len(text) <= self.max_size:
                        f.write(f"\nBody:\n{self.sanitize(text)}\n")
                    else:
                        f.write(f"\nBody: [TRUNCATED - {len(text)} bytes]\n")
                if extra:
                    try:
                        f.write(f"\nExtra:\n{json.dumps(extra, indent=2, default=str)}\n")
                    except Exception:
                        f.write(f"\nExtra (str): {extra}\n")
            self.files.append(fname)
            return fname
        except Exception:
            return None


# ============================================================
# HTTP ANALYZER (military + deception + retry)
# ============================================================
class HTTPAnalyzer:
    def __init__(self, config, scope, evidence):
        self.scope = scope
        self.evidence = evidence
        self.timeout = config["scan"]["timeout"]
        self.ua = config["scan"]["user_agent"]
        self.alt_ua = list(config["scan"]["alt_user_agents"])
        self.delay = config["scan"]["rate_limit"]
        self.retries = config["scan"]["retry_attempts"]
        self.backoff = config["scan"]["retry_backoff"]
        self.deception = config["scan"]["deception_mode"]
        self.military = config["scan"]["military_mode"]
        self._last_req = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.ua})
        self.layer_attempts = []

    def _throttle(self):
        elapsed = time.time() - self._last_req
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_req = time.time()

    def _military_headers(self, attempt_num=0):
        if not self.military:
            return {}
        tactics = [
            {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
            {"X-Forwarded-For": "10.0.0.1, 127.0.0.1", "X-Originating-IP": "10.0.0.1"},
            {"X-Client-IP": "127.0.0.1", "X-Forwarded-Host": "localhost"},
            {"CF-Connecting-IP": "127.0.0.1", "True-Client-IP": "127.0.0.1"},
            {"Forwarded": "for=127.0.0.1;proto=https;by=127.0.0.1"},
            {"X-Forwarded-For": "::1", "X-Forwarded-Proto": "https"},
            {"X-Originating-IP": "[::1]", "X-Remote-IP": "127.0.0.1"},
        ]
        tactic = tactics[attempt_num % len(tactics)]
        return tactic

    def _deception_headers(self):
        if not self.deception:
            return {}
        choices = [
            {"Referer": "https://www.google.com/"},
            {"Referer": "https://www.bing.com/search?q="},
            {"Accept": "application/json, text/plain, */*"},
            {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            {"X-Requested-With": "XMLHttpRequest"},
            {"Accept-Language": "en-US,en;q=0.9"},
            {"Cache-Control": "no-cache, no-store"},
            {"Pragma": "no-cache"},
            {"X-Client": "NikolaAudit/5.0"},
            {"X-Api-Version": "3"},
            {"DNT": "1"},
            {"Sec-Fetch-Site": "same-origin"},
            {"Sec-Fetch-Mode": "navigate"},
            {},
        ]
        return dict(random.choice(choices))

    def _attempt(self, method, url, allow_redirects, extra_headers, attempt_num):
        headers = {}
        headers.update(extra_headers or {})
        headers.update(self._deception_headers())
        if attempt_num > 0:
            headers.update(self._military_headers(attempt_num))

        r = self.session.request(
            method, url,
            timeout=(CONFIG["scan"]["connect_timeout"], self.timeout),
            allow_redirects=allow_redirects,
            verify=CONFIG["scan"]["verify_ssl"],
            headers=headers,
        )
        final_host = urlparse(r.url).hostname
        if self.scope.allowed_host and final_host != self.scope.allowed_host:
            return {
                "url": url, "error": f"Redirected out of scope to {final_host}",
                "out_of_scope_redirect": True,
            }

        set_cookies = []
        if hasattr(r.raw, "headers") and hasattr(r.raw.headers, "getlist"):
            try:
                set_cookies = r.raw.headers.getlist("Set-Cookie")
            except Exception:
                set_cookies = []
        if not set_cookies:
            raw_cookie = r.headers.get("Set-Cookie", "")
            if raw_cookie:
                set_cookies = [c.strip() for c in re.split(r",\s*(?=[^;]+=)", raw_cookie) if c.strip()]

        evidence_file = self.evidence.save(url, r)
        return {
            "url": url,
            "final_url": r.url,
            "status": r.status_code,
            "headers": dict(r.headers),
            "set_cookie": set_cookies,
            "body": r.text,
            "elapsed": r.elapsed.total_seconds(),
            "history": [h.url for h in r.history],
            "evidence_file": evidence_file,
            "timestamp": now_utc().isoformat(),
            "method": method,
            "attempts": attempt_num + 1,
            "layer": self._classify_layer(r),
        }

    def _classify_layer(self, r):
        """Identify security layer type encountered."""
        h = {k.lower(): v for k, v in r.headers.items()}
        s = r.status_code
        server = h.get("server", "").lower()
        if s == 200:
            return {"layer": "NONE", "difficulty": "OPEN", "name": "No filter"}
        if s == 403:
            if "cloudflare" in server or "cf-ray" in h:
                return {"layer": "WAF", "difficulty": "HARD", "name": "Cloudflare WAF"}
            if "akamai" in server:
                return {"layer": "WAF", "difficulty": "HARD", "name": "Akamai WAF"}
            if "sucuri" in server:
                return {"layer": "WAF", "difficulty": "MEDIUM", "name": "Sucuri WAF"}
            return {"layer": "ACL", "difficulty": "MEDIUM", "name": "Access Control"}
        if s == 429:
            return {"layer": "RATELIMIT", "difficulty": "MEDIUM", "name": "Rate limiting"}
        if s == 401:
            return {"layer": "AUTH", "difficulty": "HARD", "name": "Authentication required"}
        if s == 503:
            return {"layer": "MAINTENANCE", "difficulty": "HARD", "name": "Under attack mode"}
        if s == 406:
            return {"layer": "WAF", "difficulty": "MEDIUM", "name": "ModSecurity"}
        if s in (301, 302, 307, 308):
            return {"layer": "REDIRECT", "difficulty": "EASY", "name": "Redirect filter"}
        return {"layer": "UNKNOWN", "difficulty": "UNKNOWN", "name": f"HTTP {s}"}

    def fetch(self, url, method="GET", allow_redirects=None, headers=None):
        try:
            self.scope.validate(url)
        except ScopeError as e:
            return {"url": url, "error": str(e)}

        attempts = self.retries
        last_err = None
        ar = CONFIG["scan"]["follow_redirects"] if allow_redirects is None else allow_redirects
        last_result = None

        for i in range(attempts):
            self._throttle()
            try:
                res = self._attempt(method, url, ar, headers, i)
                if "error" in res and not res.get("out_of_scope_redirect"):
                    raise requests.exceptions.RequestException(res["error"])
                last_result = res
                layer = res.get("layer", {})
                if layer.get("layer") == "NONE":
                    break
                if i < attempts - 1:
                    wait = self.backoff[min(i, len(self.backoff) - 1)]
                    self.session.headers["User-Agent"] = self.alt_ua[i % len(self.alt_ua)]
                    print(f"   {C.Y}↻ [{i+1}/{attempts}] {layer.get('name','?')} ({layer.get('difficulty','?')}) retrying in {wait:.1f}s{C.W}")
                    time.sleep(wait)
            except requests.exceptions.SSLError as e:
                last_err = f"SSL Error: {e}"
                return {"url": url, "error": last_err, "tls_issue": True}
            except requests.exceptions.ConnectionError as e:
                last_err = f"Connection error: {e}"
            except requests.exceptions.Timeout:
                last_err = "Timeout"
            except requests.exceptions.RequestException as e:
                last_err = str(e)
            except Exception as e:
                last_err = f"Unexpected: {e}"

            if i < attempts - 1 and last_err:
                wait = self.backoff[min(i, len(self.backoff) - 1)]
                print(f"   {C.Y}↻ retry {i+1}/{attempts-1} in {wait:.1f}s ({last_err}){C.W}")
                time.sleep(wait)

        if last_result:
            return last_result
        return {"url": url, "error": last_err or "Unknown failure", "attempts": attempts}


# ============================================================
# TLS ANALYZER
# ============================================================
class TLSAnalyzer:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def analyze(self, url):
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        findings = []
        info = {"host": host, "port": port}

        if not host:
            return {"info": info, "findings": findings}

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    info["tls_version"] = ssock.version()
                    info["cipher"] = ssock.cipher()

                    if ssock.version() in ("TLSv1", "TLSv1.1", "SSLv3"):
                        findings.append({
                            "id": "TLS-001", "category": "TLS Configuration",
                            "severity": "high",
                            "title": f"Outdated TLS version: {ssock.version()}",
                            "evidence": str(ssock.cipher()),
                            "remediation": "Use TLS 1.2 or 1.3",
                        })

                    cert = ssock.getpeercert()
                    if cert and cert.get("notAfter"):
                        try:
                            expiry_ts = ssl.cert_time_to_seconds(cert["notAfter"])
                            days_left = int((expiry_ts - time.time()) / 86400)
                            info["cert_expiry_days"] = days_left
                            info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                            info["subject"] = dict(x[0] for x in cert.get("subject", []))

                            if days_left < 0:
                                findings.append({
                                    "id": "TLS-002", "category": "TLS Configuration",
                                    "severity": "critical",
                                    "title": "TLS certificate has EXPIRED",
                                    "evidence": cert["notAfter"],
                                    "remediation": "Renew the certificate immediately",
                                })
                            elif days_left < 30:
                                findings.append({
                                    "id": "TLS-003", "category": "TLS Configuration",
                                    "severity": "medium",
                                    "title": f"Certificate expires in {days_left} days",
                                    "evidence": cert["notAfter"],
                                    "remediation": "Schedule renewal",
                                })

                            issuer = info.get("issuer", {})
                            subject = info.get("subject", {})
                            if issuer and subject and issuer == subject:
                                findings.append({
                                    "id": "TLS-005", "category": "TLS Configuration",
                                    "severity": "high",
                                    "title": "Self-signed certificate detected",
                                    "evidence": str(subject),
                                    "remediation": "Use a trusted CA",
                                })
                        except Exception as e:
                            info["cert_parse_error"] = str(e)

                    cipher = ssock.cipher()
                    if cipher and cipher[0] and cipher[0].upper() in (
                        "RC4-SHA", "DES-CBC3-SHA", "NULL", "NULL-SHA", "RC4-MD5"
                    ):
                        findings.append({
                            "id": "TLS-006", "category": "TLS Configuration",
                            "severity": "high",
                            "title": f"Weak cipher: {cipher[0]}",
                            "evidence": str(cipher),
                            "remediation": "Use AEAD ciphers (AES-GCM, ChaCha20)",
                        })
        except ssl.SSLError as e:
            findings.append({
                "id": "TLS-004", "category": "TLS Configuration",
                "severity": "high",
                "title": f"SSL Error: {e}",
                "evidence": str(e),
                "remediation": "Review the certificate chain",
            })
        except Exception as e:
            info["error"] = str(e)
        return {"info": info, "findings": findings}


# ============================================================
# DNS ANALYZER
# ============================================================
class DNSAnalyzer:
    def _dig(self, name, rtype):
        dig = shutil.which("dig")
        if not dig:
            return None
        try:
            out = subprocess.check_output(
                [dig, "+short", rtype, name],
                timeout=8, stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore")
            return [l.strip() for l in out.splitlines() if l.strip()]
        except Exception:
            return None

    def _dns_python(self, name, rtype):
        try:
            import dns.resolver  # type: ignore
        except Exception:
            return None
        try:
            res = dns.resolver.Resolver()
            res.lifetime = 6
            answers = res.resolve(name, rtype)
            return [r.to_text() for r in answers]
        except Exception:
            return None

    def _resolve(self, name, rtype):
        vals = self._dig(name, rtype)
        if vals is None:
            vals = self._dns_python(name, rtype)
        return vals

    def analyze(self, url):
        parsed = urlparse(url)
        host = parsed.hostname
        findings = []
        info = {"host": host}

        if not host:
            return {"info": info, "findings": findings}

        apex = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host

        a = self._resolve(host, "A") or []
        aaaa = self._resolve(host, "AAAA") or []
        mx = self._resolve(apex, "MX") or []
        ns = self._resolve(apex, "NS") or []
        txt = self._resolve(apex, "TXT") or []
        caa = self._resolve(apex, "CAA") or []
        ds = self._resolve(apex, "DS") or []
        dnskey = self._resolve(apex, "DNSKEY") or []

        info.update({
            "apex": apex, "A": a, "AAAA": aaaa, "MX": mx, "NS": ns,
            "TXT_count": len(txt), "CAA": caa,
            "DNSSEC_DS": ds, "DNSSEC_DNSKEY": dnskey,
        })

        spf = [t for t in txt if "v=spf1" in t]
        dmarc = self._resolve(f"_dmarc.{apex}", "TXT") or []
        dmarc_records = [t for t in dmarc if "v=DMARC1" in t]

        info["SPF"] = spf
        info["DMARC"] = dmarc_records

        if not spf:
            findings.append({
                "id": "DNS-001", "category": "DNS Security",
                "severity": "medium", "title": "No SPF record found",
                "evidence": f"TXT on {apex} = {txt[:3]}",
                "remediation": "Add SPF: v=spf1 include:_spf.provider.com -all",
            })
        else:
            spf_val = spf[0]
            if "~all" in spf_val:
                findings.append({
                    "id": "DNS-002", "category": "DNS Security",
                    "severity": "low", "title": "SPF uses soft-fail (~all)",
                    "evidence": spf_val[:200], "remediation": "Use strict -all",
                })
            if "+all" in spf_val:
                findings.append({
                    "id": "DNS-003", "category": "DNS Security",
                    "severity": "critical", "title": "SPF is +all (spoofable)",
                    "evidence": spf_val[:200], "remediation": "Change to -all",
                })

        if not dmarc_records:
            findings.append({
                "id": "DNS-004", "category": "DNS Security",
                "severity": "medium", "title": "No DMARC record found",
                "evidence": f"_dmarc.{apex} TXT empty",
                "remediation": "Add: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain",
            })
        else:
            d = dmarc_records[0]
            info["DMARC_policy"] = d
            if "p=none" in d:
                findings.append({
                    "id": "DNS-005", "category": "DNS Security",
                    "severity": "low", "title": "DMARC policy is none",
                    "evidence": d[:200], "remediation": "Move to p=quarantine then p=reject",
                })

        if not ds and not dnskey:
            findings.append({
                "id": "DNS-006", "category": "DNS Security",
                "severity": "low", "title": "DNSSEC not detected",
                "evidence": f"DS={ds}, DNSKEY={dnskey}",
                "remediation": "Enable DNSSEC",
            })
        else:
            info["DNSSEC_enabled"] = True

        if not caa:
            findings.append({
                "id": "DNS-007", "category": "DNS Security",
                "severity": "low", "title": "No CAA record",
                "evidence": f"CAA on {apex} = []",
                "remediation": "Add CAA to restrict cert issuance",
            })
        else:
            info["CAA_records"] = caa

        if ns:
            info["NS_list"] = ns[:5]

        return {"info": info, "findings": findings}


# ============================================================
# ASSET DISCOVERY
# ============================================================
class AssetDiscovery:
    def __init__(self, analyzer):
        self.analyzer = analyzer

    def _analyze_assets(self, http_result):
        assets = {
            "links": [], "forms": [], "scripts": [], "images": [],
            "api_endpoints": [], "robots": None, "sitemap": None,
            "comments": [], "meta": {}, "inline_scripts": [],
            "external_domains": set(), "tech": set(),
        }
        try:
            base = http_result.get("final_url") or http_result.get("url", "")
            base_host = urlparse(base).hostname
            body = http_result.get("body", "") or ""
            soup = BeautifulSoup(body, "html.parser")

            links = set()
            for a in soup.find_all("a", href=True):
                full = urljoin(base, a["href"])
                h = urlparse(full).hostname
                if h and h == base_host:
                    links.add(full)
                elif h:
                    assets["external_domains"].add(h)
            assets["links"] = sorted(links)[:CONFIG["scan"]["max_links"]]

            for f in soup.find_all("form"):
                action = urljoin(base, f.get("action", base))
                method = (f.get("method") or "GET").upper()
                inputs = []
                for i in f.find_all(["input", "textarea", "select"]):
                    inputs.append({
                        "name": i.get("name") or "unknown",
                        "type": (i.get("type") or "text"),
                        "autocomplete": i.get("autocomplete") or "",
                        "required": i.has_attr("required"),
                        "pattern": i.get("pattern") or "",
                        "maxlength": i.get("maxlength") or "",
                    })
                assets["forms"].append({"action": action, "method": method, "inputs": inputs})

            for s in soup.find_all("script", src=True):
                full = urljoin(base, s["src"])
                assets["scripts"].append(full)
                if urlparse(full).hostname != base_host:
                    assets["external_domains"].add(urlparse(full).hostname)

            for s in soup.find_all("script"):
                if s.string and len(s.string.strip()) > 20:
                    assets["inline_scripts"].append(s.string.strip()[:500])

            for i in soup.find_all("img", src=True):
                assets["images"].append(urljoin(base, i["src"]))

            api_pattern = re.compile(r"['\"](/api/[\w\-/\.?=&]+|/v\d/[\w\-/\.?=&]+|/graphql|/rest/[\w\-/]+)['\"]")
            for m in api_pattern.finditer(body):
                assets["api_endpoints"].append(m.group(1))
            assets["api_endpoints"] = sorted(set(assets["api_endpoints"]))

            for c in soup.find_all(string=lambda t: isinstance(t, type(soup.Comment))):
                assets["comments"].append(str(c).strip()[:300])

            for m in soup.find_all("meta"):
                if m.get("name"):
                    assets["meta"][m["name"]] = m.get("content", "")

            hdrs = {k.lower(): v.lower() for k, v in http_result.get("headers", {}).items()}
            cookies = " ".join(http_result.get("set_cookie", [])).lower()
            full_lower = body.lower()
            tech_sig = {
                "wordpress": ["wp-content", "wp-includes"],
                "drupal": ["drupal", "sites/default/files"],
                "joomla": ["joomla", "/media/jui/"],
                "react": ["react.development", "react.production", "_react"],
                "vue": ["vue.min.js", "__vue__"],
                "angular": ["ng-version", "angular.min.js"],
                "next.js": ["__next_data__"],
                "laravel": ["laravel_session"],
                "django": ["csrftoken", "django"],
                "php": ["phpsessid"],
                "java": ["jsessionid"],
                "asp.net": ["asp.net_sessionid", "__viewstate"],
                "nginx": ["nginx"],
                "cloudflare": ["cf-ray"],
                "bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
                "jquery": ["jquery.min.js", "jquery-"],
                "shopify": ["shopify"],
                "magento": ["mage/cookies"],
            }
            haystack = f"{full_lower} {cookies} {hdrs.get('server','')}"
            for name, sigs in tech_sig.items():
                for sig in sigs:
                    if sig in haystack:
                        assets["tech"].add(name)
                        break

            assets["robots"] = self._fetch_text(urljoin(base, "/robots.txt"))
            assets["sitemap"] = self._fetch_text(urljoin(base, "/sitemap.xml"))
        except Exception as e:
            print(f"   {C.R}⚠ Asset discovery: {e}{C.W}")

        assets["external_domains"] = sorted(assets["external_domains"])
        assets["tech"] = sorted(assets["tech"])
        return assets

    def _fetch_text(self, url):
        r = self.analyzer.fetch(url)
        if "error" in r or r.get("status") != 200:
            return None
        return (r.get("body") or "")[:5000]

    def discover(self, http_result):
        print(f"\n{C.Y}[*] Asset Discovery...{C.W}")
        assets = self._analyze_assets(http_result)
        print(f"   {C.G}✓ Links: {len(assets['links'])}")
        print(f"   {C.G}✓ Forms: {len(assets['forms'])}")
        print(f"   {C.G}✓ Scripts: {len(assets['scripts'])}")
        print(f"   {C.G}✓ API endpoints: {len(assets['api_endpoints'])}")
        print(f"   {C.G}✓ Tech: {', '.join(assets['tech']) or 'n/a'}")
        print(f"   {C.G}✓ robots.txt: {'✓' if assets['robots'] else '✗'}")
        print(f"   {C.G}✓ sitemap.xml: {'✓' if assets['sitemap'] else '✗'}{C.W}")
        return assets


# ============================================================
# MODULES
# ============================================================
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("medium", "Add: max-age=31536000; includeSubDomains"),
    "Content-Security-Policy": ("high", "Set CSP with default-src 'self'"),
    "X-Content-Type-Options": ("low", "Add: nosniff"),
    "X-Frame-Options": ("medium", "Add: DENY or SAMEORIGIN"),
    "Referrer-Policy": ("low", "Add: strict-origin-when-cross-origin"),
    "Permissions-Policy": ("low", "Restrict unused features"),
    "Cross-Origin-Opener-Policy": ("low", "Add: same-origin"),
    "Cross-Origin-Resource-Policy": ("low", "Add: same-origin"),
}


def module_security_headers(http_result, **ctx):
    findings = []
    headers = {k.lower(): v for k, v in http_result.get("headers", {}).items()}
    for header, (sev, fix) in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            findings.append({
                "id": f"HDR-{header[:3].upper()}",
                "category": "Security Headers",
                "severity": sev,
                "title": f"Missing header: {header}",
                "evidence": f"Response does not include {header}",
                "remediation": fix,
            })
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15552000:
            findings.append({
                "id": "HDR-HSTS-WEAK", "category": "Security Headers",
                "severity": "medium", "title": "HSTS max-age is too short",
                "evidence": hsts, "remediation": "Set max-age=31536000",
            })
    csp = headers.get("content-security-policy", "")
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp):
        findings.append({
            "id": "HDR-CSP-WEAK", "category": "Security Headers",
            "severity": "medium", "title": "CSP includes unsafe-inline/unsafe-eval/*",
            "evidence": csp[:150], "remediation": "Remove unsafe-* from CSP",
        })
    return findings


INFO_PATTERNS = [
    (r"(?i)x-powered-by", "medium", "X-Powered-By leaked"),
    (r"Server:\s*Apache/[\d\.]+", "low", "Apache version leaked"),
    (r"Server:\s*nginx/[\d\.]+", "low", "Nginx version leaked"),
    (r"Server:\s*IIS/[\d\.]+", "low", "IIS version leaked"),
    (r"(?i)stack trace", "high", "Stack trace leaked"),
    (r"(?i)(sql syntax|mysql_fetch|ORA-\d+|postgres.*error)", "critical", "SQL error leaked"),
    (r"(?i)phpinfo\(\)", "high", "phpinfo leaked"),
    (r"(?i)index of /", "medium", "Directory listing"),
    (r"<!--\s*(TODO|FIXME|password|admin)", "medium", "Sensitive comment"),
    (r"(?i)debug\s*=\s*true", "high", "Debug mode enabled"),
    (r"(?i)wp-content|wp-includes", "info", "WordPress detected"),
    (r"(?i)(access[_-]?key|secret[_-]?key)\s*[:=]\s*['\"]?[\w\-]{12,}", "critical", "API key/secret leaked"),
    (r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----", "critical", "Private key leaked"),
    (r"AKIA[0-9A-Z]{16}", "critical", "AWS Access Key ID leaked"),
    (r"(?i)(mongodb|mysql|postgres)://[^\s\"']+", "critical", "Database URI leaked"),
]


def module_info_disclosure(http_result, **ctx):
    findings = []
    combined = str(http_result.get("headers", {})) + "\n" + (http_result.get("body") or "")
    for pattern, sev, title in INFO_PATTERNS:
        m = re.search(pattern, combined)
        if m:
            findings.append({
                "id": f"DISC-{abs(hash(pattern)) % 1000:03d}",
                "category": "Information Disclosure",
                "severity": sev, "title": title,
                "evidence": m.group(0)[:160],
                "remediation": "Hide versions/errors in production",
            })
    return findings


def module_cookies(http_result, **ctx):
    findings = []
    cookies = http_result.get("set_cookie", [])
    if not cookies:
        return findings
    for c in cookies:
        name = (c.split("=")[0].strip() or "unknown_cookie")
        low = c.lower()
        if "secure" not in low:
            findings.append({
                "id": "COOK-001", "category": "Cookie Security",
                "severity": "medium", "title": f"Cookie '{name}' missing Secure",
                "evidence": c[:120], "remediation": "Add Secure flag",
            })
        if "httponly" not in low:
            findings.append({
                "id": "COOK-002", "category": "Cookie Security",
                "severity": "medium", "title": f"Cookie '{name}' missing HttpOnly",
                "evidence": c[:120], "remediation": "Add HttpOnly",
            })
        if "samesite" not in low:
            findings.append({
                "id": "COOK-003", "category": "Cookie Security",
                "severity": "low", "title": f"Cookie '{name}' missing SameSite",
                "evidence": c[:120], "remediation": "Add SameSite=Lax/Strict",
            })
    return findings


def module_cors(http_result, **ctx):
    findings = []
    h = {k.lower(): v for k, v in http_result.get("headers", {}).items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        findings.append({
            "id": "CORS-001", "category": "CORS Configuration",
            "severity": "critical", "title": "CORS wildcard + credentials",
            "evidence": f"ACAO={acao}, ACAC={acac}",
            "remediation": "Set specific origin, not *",
        })
    elif acao == "*":
        findings.append({
            "id": "CORS-002", "category": "CORS Configuration",
            "severity": "low", "title": "CORS allows *",
            "evidence": f"ACAO={acao}", "remediation": "Use a whitelist",
        })
    return findings


def module_config_audit(http_result, assets=None, **ctx):
    findings = []
    headers = {k.lower(): v for k, v in http_result.get("headers", {}).items()}
    server = headers.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        findings.append({
            "id": "CFG-001", "category": "Configuration Audit",
            "severity": "low", "title": "Server banner exposes version",
            "evidence": server, "remediation": "Hide server version",
        })
    if http_result.get("url", "").startswith("http://"):
        findings.append({
            "id": "CFG-002", "category": "Configuration Audit",
            "severity": "high", "title": "Site uses HTTP (not HTTPS)",
            "evidence": http_result.get("url", ""),
            "remediation": "Enforce HTTPS",
        })
    if "index of /" in (http_result.get("body") or "").lower():
        findings.append({
            "id": "CFG-003", "category": "Configuration Audit",
            "severity": "medium", "title": "Directory listing enabled",
            "evidence": "Body contains 'Index of /'",
            "remediation": "Disable autoindex",
        })
    if assets and assets.get("robots"):
        for line in assets["robots"].splitlines():
            if line.lower().startswith("disallow:") and any(
                k in line.lower() for k in ["admin", "backup", "config", "private", ".git", ".env"]
            ):
                findings.append({
                    "id": "CFG-004", "category": "Configuration Audit",
                    "severity": "low", "title": "robots.txt reveals sensitive path",
                    "evidence": line[:120],
                    "remediation": "Don't put sensitive paths in robots.txt",
                })
                break
    hsts = headers.get("strict-transport-security")
    if http_result.get("url", "").startswith("https") and not hsts:
        findings.append({
            "id": "CFG-005", "category": "Configuration Audit",
            "severity": "medium", "title": "HTTPS without HSTS",
            "evidence": "HSTS header missing",
            "remediation": "Add Strict-Transport-Security",
        })
    return findings


def module_auth_review(http_result, assets=None, **ctx):
    findings = []
    headers = {k.lower(): v for k, v in http_result.get("headers", {}).items()}

    if assets and assets.get("forms"):
        for form in assets["forms"]:
            has_pwd = any(i["type"] == "password" for i in form["inputs"])
            if not has_pwd:
                continue
            has_csrf = any(
                "csrf" in i["name"].lower() or "token" in i["name"].lower()
                for i in form["inputs"]
            )
            if not has_csrf:
                findings.append({
                    "id": "AUTH-001", "category": "Authentication Review",
                    "severity": "high", "title": "Login form lacks CSRF token",
                    "evidence": f"Form action: {form['action']}",
                    "remediation": "Add CSRF token to all forms",
                })

    if "www-authenticate" in headers and http_result.get("url", "").startswith("http://"):
        findings.append({
            "id": "AUTH-003", "category": "Authentication Review",
            "severity": "high", "title": "Basic Auth over HTTP",
            "evidence": headers["www-authenticate"],
            "remediation": "Use HTTPS only with Basic Auth",
        })

    soup = BeautifulSoup(http_result.get("body") or "", "html.parser")
    title = (soup.title.string or "").lower() if soup.title else ""
    if any(k in title for k in ["login", "sign in", "account"]):
        if http_result.get("url", "").startswith("http://"):
            findings.append({
                "id": "AUTH-004", "category": "Authentication Review",
                "severity": "critical", "title": "Login page served over HTTP",
                "evidence": http_result.get("url", ""),
                "remediation": "HTTPS mandatory for login",
            })
    return findings


SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config", ".env", ".svn/entries",
    "backup.sql", "config.php.bak", "wp-config.php.bak",
    "phpinfo.php", ".DS_Store", "server-status",
    "web.config", "id_rsa", "composer.lock", "package.json",
    "Dockerfile", "docker-compose.yml", ".aws/credentials",
    "credentials.json", "api-docs.json", "swagger.json",
    ".htaccess", ".htpasswd", "console", "actuator/env",
]


def module_access_control(http_result, assets=None, analyzer=None, **ctx):
    findings = []
    body = (http_result.get("body") or "").lower()
    if "index of /" in body:
        findings.append({
            "id": "AC-001", "category": "Access Control",
            "severity": "high", "title": "Directory listing permits access",
            "evidence": "Index of /", "remediation": "Disable directory listing",
        })

    max_checks = CONFIG["scan"].get("max_extra_checks", 14)
    if analyzer and assets:
        checked = 0
        for path in SENSITIVE_PATHS:
            if checked >= max_checks:
                break
            checked += 1
            try:
                base = (http_result.get("final_url") or "").rstrip("/")
                url = f"{base}/{path}"
                r = analyzer.fetch(url)
                if "error" in r:
                    continue
                status = r.get("status")
                if status == 200:
                    rb = (r.get("body") or "").lower()
                    is_real = True
                    if path.endswith((".env", ".sql", ".bak", ".lock", ".json")) and "<html" in rb:
                        is_real = False
                    if is_real:
                        findings.append({
                            "id": "AC-002", "category": "Access Control",
                            "severity": "critical",
                            "title": f"Sensitive path exposed: /{path}",
                            "evidence": f"HTTP 200 on {url}",
                            "remediation": f"Block access to /{path}",
                        })
            except Exception:
                pass
    return findings


def module_input_validation(http_result, assets=None, **ctx):
    findings = []
    if not assets or not assets.get("forms"):
        return findings

    for form in assets["forms"]:
        for i in form["inputs"]:
            if i["type"] == "hidden":
                findings.append({
                    "id": "INP-001", "category": "Input Validation",
                    "severity": "info", "title": f"Hidden input: {i['name']}",
                    "evidence": f"Form: {form['action']}",
                    "remediation": "Ensure hidden values cannot be tampered with",
                })
            if i["type"] == "file":
                findings.append({
                    "id": "INP-002", "category": "Input Validation",
                    "severity": "medium", "title": f"File upload input: {i['name']}",
                    "evidence": f"Form: {form['action']}",
                    "remediation": "Validate file type/size server-side",
                })

        if form["method"] == "GET" and any(i["type"] == "password" for i in form["inputs"]):
            findings.append({
                "id": "INP-003", "category": "Input Validation",
                "severity": "critical", "title": "Password field in GET form",
                "evidence": f"Form action: {form['action']}",
                "remediation": "Use POST for sensitive data",
            })
    return findings


def module_api_security(http_result, assets=None, analyzer=None, **ctx):
    findings = []
    if assets and assets.get("api_endpoints"):
        eps = assets["api_endpoints"][:10]
        findings.append({
            "id": "API-001", "category": "API Security",
            "severity": "info",
            "title": f"API endpoints discovered ({len(eps)})",
            "evidence": ", ".join(eps),
            "remediation": "Ensure all endpoints require auth + rate limiting",
        })
    return findings


def module_session_security(http_result, **ctx):
    findings = []
    cookies = http_result.get("set_cookie", [])
    for c in cookies:
        low = c.lower()
        name = (c.split("=")[0].strip() or "unknown_cookie")
        if any(k in name.lower() for k in ["sess", "session", "auth", "sid", "jwt"]):
            if "secure" not in low:
                findings.append({
                    "id": "SESS-001", "category": "Session Security",
                    "severity": "high",
                    "title": f"Session cookie '{name}' missing Secure",
                    "evidence": c[:120], "remediation": "Add Secure",
                })
            if "httponly" not in low:
                findings.append({
                    "id": "SESS-003", "category": "Session Security",
                    "severity": "high",
                    "title": f"Session cookie '{name}' missing HttpOnly",
                    "evidence": c[:120], "remediation": "Add HttpOnly",
                })
    return findings


def module_auth_security_auditor(http_result, assets=None, **ctx):
    findings = []
    cookies = http_result.get("set_cookie", [])
    body_low = (http_result.get("body") or "").lower()

    if any(m in body_low for m in ["password", "login", "signin"]):
        if not any(k in body_low for k in ["captcha", "recaptcha", "hcaptcha"]):
            findings.append({
                "id": "AUTHSEC-001", "category": "Authentication Security",
                "severity": "medium", "title": "Login page has no CAPTCHA",
                "evidence": "No captcha markers",
                "remediation": "Add CAPTCHA / rate-limiting",
            })
        if not any(k in body_low for k in ["2fa", "two-factor", "otp"]):
            findings.append({
                "id": "AUTHSEC-003", "category": "Authentication Security",
                "severity": "low", "title": "No MFA hint on login page",
                "evidence": "No MFA marker",
                "remediation": "Offer 2FA",
            })

    if cookies:
        total = len(cookies)
        secure_cnt = sum(1 for c in cookies if "secure" in c.lower())
        if secure_cnt < total:
            findings.append({
                "id": "AUTHSEC-006", "category": "Authentication Security",
                "severity": "medium",
                "title": f"Cookie hygiene: {secure_cnt}/{total} Secure",
                "evidence": f"cookie count={total}",
                "remediation": "All auth cookies must be Secure+HttpOnly+SameSite",
            })
    return findings


KNOWN_VULN_DB = {
    "jquery": {"1.": "Old jQuery has XSS CVEs; upgrade.", "2.": "CVE-2020-11022/11023; upgrade.", "3.0": "CVE-2020-11022/11023; upgrade to 3.7+.", "3.1": "Upgrade to 3.7+.", "3.2": "Upgrade to 3.7+.", "3.3": "Upgrade to 3.7+.", "3.4": "Upgrade to 3.7+."},
    "bootstrap": {"2.": "Old XSS; upgrade.", "3.0": "CVE-2018-14040 etc; upgrade.", "3.3": "Upgrade to 4.6+/5.x.", "4.0": "Upgrade to 4.6+/5.x.", "4.5": "Upgrade to 4.6+."},
    "angular": {"1.": "AngularJS EOL; migrate."},
    "lodash": {"4.17.0": "CVE-2019-10744; upgrade.", "4.17.11": "Upgrade to 4.17.21+.", "4.17.15": "Upgrade to 4.17.21+.", "4.17.19": "Upgrade to 4.17.21+."},
    "moment": {"2.19": "Upgrade to 2.29.4+.", "2.24": "Upgrade to 2.29.4+.", "2.27": "Upgrade to 2.29.4+."},
    "axios": {"0.21": "SSRF CVE-2021-3749; upgrade.", "0.24": "Upgrade to 1.x.", "0.27": "Upgrade to 1.x."},
}

LIB_REGEXES = [
    (re.compile(r"jquery[.-]?v?(\d+\.\d+(?:\.\d+)?)", re.I), "jquery"),
    (re.compile(r"bootstrap(?:\.min)?\.(?:css|js)[^\"']*?v?(\d+\.\d+(?:\.\d+)?)", re.I), "bootstrap"),
    (re.compile(r"angular(?:\.min)?\.js[^\"']*?v?(\d+\.\d+(?:\.\d+)?)", re.I), "angular"),
    (re.compile(r"lodash(?:\.min)?\.js[^\"']*?v?(\d+\.\d+(?:\.\d+)?)", re.I), "lodash"),
    (re.compile(r"moment(?:\.min)?\.js[^\"']*?v?(\d+\.\d+(?:\.\d+)?)", re.I), "moment"),
    (re.compile(r"axios(?:\.min)?\.js[^\"']*?v?(\d+\.\d+(?:\.\d+)?)", re.I), "axios"),
]


def _lib_vuln_lookup(lib, version):
    db = KNOWN_VULN_DB.get(lib, {})
    for key, advisory in db.items():
        if version.startswith(key):
            return advisory
    return None


def module_dependency_security(http_result, assets=None, **ctx):
    findings = []
    combined = (http_result.get("body") or "") + " " + str(http_result.get("headers", {}))
    if assets:
        combined += " " + " ".join(assets.get("scripts", []))
        combined += " " + " ".join(assets.get("inline_scripts", []))

    found = {}
    for rx, name in LIB_REGEXES:
        for m in rx.finditer(combined):
            ver = m.group(1)
            if ver:
                found.setdefault(name, set()).add(ver)

    for lib, versions in found.items():
        for ver in sorted(versions):
            advisory = _lib_vuln_lookup(lib, ver)
            if advisory:
                findings.append({
                    "id": "DEP-001", "category": "Dependency Security",
                    "severity": "high",
                    "title": f"{lib} {ver} has known issues",
                    "evidence": advisory,
                    "remediation": "Upgrade dependency",
                })
    return findings


def module_content_security(http_result, assets=None, **ctx):
    findings = []
    h = {k.lower(): v for k, v in http_result.get("headers", {}).items()}
    body = http_result.get("body") or ""
    url = http_result.get("url", "")

    csp = h.get("content-security-policy", "")
    if not csp:
        findings.append({
            "id": "CONTENT-001", "category": "Content Security",
            "severity": "high", "title": "No Content-Security-Policy",
            "evidence": "CSP header missing",
            "remediation": "Deploy CSP",
        })
    else:
        if "default-src" not in csp.lower():
            findings.append({
                "id": "CONTENT-002", "category": "Content Security",
                "severity": "medium", "title": "CSP missing default-src",
                "evidence": csp[:200], "remediation": "Add default-src 'self'",
            })

    if url.startswith("https"):
        for m in re.finditer(r"http://[^\s\"'<>)]+", body):
            u = m.group(0)
            if not u.startswith("http://localhost"):
                findings.append({
                    "id": "CONTENT-005", "category": "Content Security",
                    "severity": "medium", "title": "Mixed content URL",
                    "evidence": u[:160], "remediation": "Serve via HTTPS",
                })
                break
    return findings


class VulnerabilityDetector:
    def __init__(self):
        self.modules = [
            ("Security Headers", module_security_headers),
            ("Information Disclosure", module_info_disclosure),
            ("Cookie Security", module_cookies),
            ("CORS Configuration", module_cors),
            ("Configuration Audit", module_config_audit),
            ("Authentication Review", module_auth_review),
            ("Access Control", module_access_control),
            ("Input Validation", module_input_validation),
            ("API Security", module_api_security),
            ("Session Security", module_session_security),
            ("Authentication Security", module_auth_security_auditor),
            ("Dependency Security", module_dependency_security),
            ("Content Security", module_content_security),
        ]

    def run(self, http_result, **ctx):
        all_findings = []
        for name, fn in self.modules:
            try:
                found = fn(http_result, **ctx) or []
                if found:
                    all_findings.extend(found)
                color = C.G if len(found) == 0 else C.Y
                print(f"   {color}✓ {name}: {len(found)} findings{C.W}")
            except Exception as e:
                print(f"   {C.R}⚠ {name}: {e}{C.W}")
        return all_findings


# ============================================================
# REPORTING
# ============================================================
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_sort_key(f):
    return SEVERITY_ORDER.get(f.get("severity", "info"), 9)


def _html_escape(s):
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;"))


class ReportEngine:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate(self, target, findings, metadata=None, evidence_files=None):
        findings = sorted(findings, key=_severity_sort_key)
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            summary[sev] = summary.get(sev, 0) + 1

        by_category = {}
        for f in findings:
            by_category.setdefault(f.get("category", "Other"), []).append(f)

        report = {
            "tool": CONFIG["author"]["tool"],
            "version": CONFIG["author"]["version"],
            "author": CONFIG["author"],
            "run_id": self.run_id,
            "target": target,
            "timestamp": now_utc().isoformat() + "Z",
            "summary": summary,
            "by_category": {k: len(v) for k, v in by_category.items()},
            "metadata": metadata or {},
            "evidence_files": evidence_files or [],
            "findings": findings,
        }

        jpath = f"{self.output_dir}/{self.run_id}_report.json"
        tpath = f"{self.output_dir}/{self.run_id}_report.txt"
        hpath = f"{self.output_dir}/{self.run_id}_report.html"
        with open(jpath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        with open(tpath, "w", encoding="utf-8") as f:
            f.write(self._txt(report, by_category))
        with open(hpath, "w", encoding="utf-8") as f:
            f.write(self._html(report, by_category))

        self._append_history(report, hpath)

        return {"json": jpath, "txt": tpath, "html": hpath, "summary": summary,
                "total": len(findings), "run_id": self.run_id}

    def _append_history(self, report, html_path):
        hist_file = CONFIG["history_file"]
        os.makedirs(os.path.dirname(hist_file) or ".", exist_ok=True)
        history = []
        if os.path.exists(hist_file):
            try:
                with open(hist_file, "r", encoding="utf-8") as f:
                    history = json.load(f)
            except Exception:
                history = []
        history.append({
            "run_id": report["run_id"],
            "target": report["target"],
            "timestamp": report["timestamp"],
            "summary": report["summary"],
            "total": len(report["findings"]),
            "html": html_path,
        })
        try:
            with open(hist_file, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception:
            pass

    def _txt(self, r, by_cat):
        a = r["author"]
        lines = [
            "=" * 66,
            f"  {a['tool']} v{r['version']} REPORT - {r['run_id']}",
            "=" * 66,
            f"Author : {a['name']} ({a['country']}) | {a['email']}",
            "-" * 66,
            f"Target : {r['target']}",
            f"Time   : {r['timestamp']}",
            "",
            "SUMMARY:",
        ]
        for k, v in r["summary"].items():
            lines.append(f"  [{k.upper():8}] {v}")
        for cat, items in by_cat.items():
            lines.append(f"\n### {cat} ({len(items)})")
            for i, f in enumerate(items, 1):
                lines.append(f"  [{i}] [{f['severity'].upper()}] {f['title']}")
                lines.append(f"      ID: {f.get('id', '-')}")
                lines.append(f"      Evidence: {str(f.get('evidence','-'))[:140]}")
                lines.append(f"      Fix: {f.get('remediation', '-')}")
        return "\n".join(lines)

    def _html(self, r, by_cat):
        a = r["author"]
        cat_sections = ""
        for cat, items in by_cat.items():
            rows = "".join(
                f"<tr class='sev-row-{f['severity']}'>"
                f"<td><span class='pill pill-{f['severity']}'>{f['severity'].upper()}</span></td>"
                f"<td class='id'>{f.get('id','-')}</td>"
                f"<td>{_html_escape(f['title'])}</td>"
                f"<td class='ev'>{_html_escape(str(f.get('evidence',''))[:220])}</td>"
                f"<td>{_html_escape(str(f.get('remediation','')))}</td>"
                f"</tr>"
                for f in items
            )
            cat_sections += f"""
<section class="cat">
<h2>{_html_escape(cat)}<span class="count">{len(items)}</span></h2>
<table><thead><tr>
<th style="width:90px">Severity</th><th style="width:100px">ID</th>
<th>Title</th><th>Evidence</th><th style="width:280px">Remediation</th>
</tr></thead><tbody>{rows}</tbody></table>
</section>"""

        summary_cards = "".join(
            f'<div class="scard sc-{k}"><div class="sc-label">{k.upper()}</div><div class="sc-val">{v}</div></div>'
            for k, v in r["summary"].items()
        )

        meta = r.get("metadata", {})
        assets_info = meta.get("assets", {})
        asset_rows = "".join(
            f"<tr><td>{_html_escape(str(k))}</td><td class='mono'>{_html_escape(str(v))}</td></tr>"
            for k, v in assets_info.items()
        )
        dns_info = meta.get("dns", {}) or {}
        dns_rows = "".join(
            f"<tr><td>{_html_escape(str(k))}</td><td class='mono'>{_html_escape(str(v))[:250]}</td></tr>"
            for k, v in dns_info.items()
            if k in ("apex", "A", "AAAA", "NS_list", "SPF", "DMARC", "DMARC_policy", "DNSSEC_enabled", "CAA_records")
        )
        tls_info = meta.get("tls", {}) or {}
        tls_rows = "".join(
            f"<tr><td>{_html_escape(str(k))}</td><td class='mono'>{_html_escape(str(v))[:250]}</td></tr>"
            for k, v in tls_info.items()
            if k in ("tls_version", "cipher", "cert_expiry_days", "issuer", "subject")
        )

        layers = meta.get("layers", []) or []
        layers_html = ""
        if layers:
            lrows = "".join(
                f"<tr><td>{_html_escape(str(l.get('name','?')))}</td>"
                f"<td><span class='pill pill-{_layer_pill(l.get('difficulty','UNKNOWN'))}'>{_html_escape(str(l.get('difficulty','?')))}</span></td>"
                f"<td>{_html_escape(str(l.get('layer','?')))}</td></tr>"
                for l in layers
            )
            layers_html = f"""
<section class="cat">
<h2>Security Layers Encountered<span class="count">{len(layers)}</span></h2>
<table><thead><tr><th>Layer</th><th>Difficulty</th><th>Type</th></tr></thead>
<tbody>{lrows}</tbody></table>
</section>"""

        return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{a['tool']} — {r['run_id']}</title>
<style>
  :root {{
    --bg:#0a0e14; --bg2:#0f141d; --panel:#121923; --panel2:#1a2330;
    --border:#232d3d; --text:#c9d6e3; --dim:#6b7a8c;
    --accent:#00d4ff; --accent2:#00ff9d; --crit:#ff4757; --high:#ff8a3d;
    --med:#ffc107; --low:#3ddc84; --info:#58a6ff;
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;font-family:"Inter","Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.55;font-size:14px}}
  header{{background:linear-gradient(135deg,#0a0e14,#121923 60%,#0a0e14);border-bottom:1px solid var(--border);padding:22px 32px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px}}
  .brand h1{{margin:0;font-size:20px;letter-spacing:3px;color:var(--accent2);font-weight:800}}
  .brand .sub{{color:var(--dim);font-size:12px;letter-spacing:1px;margin-top:3px}}
  .chip{{background:var(--panel2);border:1px solid var(--border);border-radius:20px;padding:6px 14px;font-size:12px;color:var(--accent);font-family:"Courier New",monospace}}
  main{{max-width:1280px;margin:0 auto;padding:28px 32px 80px}}
  h2{{font-size:16px;letter-spacing:1.2px;text-transform:uppercase;color:var(--accent);margin:38px 0 12px;display:flex;align-items:center;gap:12px;font-weight:700}}
  h2::before{{content:"";display:block;width:4px;height:16px;background:var(--accent2);border-radius:2px}}
  h2 .count{{margin-left:auto;background:var(--panel2);color:var(--dim);font-size:11px;padding:3px 10px;border-radius:10px;letter-spacing:1px;font-weight:600}}
  .info-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:16px}}
  .info-card{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px}}
  .info-card .k{{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;font-weight:600}}
  .info-card .v{{color:var(--text);font-size:13px;word-break:break-all;font-family:"Courier New",monospace}}
  .scards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-top:16px}}
  .scard{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;position:relative;overflow:hidden}}
  .scard::before{{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--dim)}}
  .sc-critical::before{{background:var(--crit)}} .sc-high::before{{background:var(--high)}}
  .sc-medium::before{{background:var(--med)}} .sc-low::before{{background:var(--low)}} .sc-info::before{{background:var(--info)}}
  .sc-label{{font-size:11px;letter-spacing:1.5px;color:var(--dim);font-weight:700}}
  .sc-val{{font-size:26px;font-weight:800;margin-top:6px;color:var(--text)}}
  table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-top:10px}}
  th{{background:var(--panel2);color:var(--accent);font-size:11px;letter-spacing:1px;text-transform:uppercase;padding:11px 14px;text-align:left;border-bottom:1px solid var(--border);font-weight:700}}
  td{{padding:11px 14px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:rgba(0,212,255,.03)}}
  .pill{{display:inline-block;font-size:10px;padding:3px 9px;border-radius:8px;font-weight:800;letter-spacing:.6px}}
  .pill-critical{{background:rgba(255,71,87,.15);color:var(--crit);border:1px solid rgba(255,71,87,.4)}}
  .pill-high{{background:rgba(255,138,61,.15);color:var(--high);border:1px solid rgba(255,138,61,.4)}}
  .pill-medium{{background:rgba(255,193,7,.15);color:var(--med);border:1px solid rgba(255,193,7,.4)}}
  .pill-low{{background:rgba(61,220,132,.15);color:var(--low);border:1px solid rgba(61,220,132,.4)}}
  .pill-info{{background:rgba(88,166,255,.15);color:var(--info);border:1px solid rgba(88,166,255,.4)}}
  .pill-hard{{background:rgba(255,71,87,.15);color:var(--crit);border:1px solid rgba(255,71,87,.4)}}
  .pill-standard{{background:rgba(255,193,7,.15);color:var(--med);border:1px solid rgba(255,193,7,.4)}}
  .pill-easy{{background:rgba(61,220,132,.15);color:var(--low);border:1px solid rgba(61,220,132,.4)}}
  .pill-open{{background:rgba(0,255,157,.2);color:var(--accent2);border:1px solid rgba(0,255,157,.4)}}
  .pill-unknown{{background:var(--panel2);color:var(--dim);border:1px solid var(--border)}}
  .ev, .mono, .id{{font-family:"Courier New",monospace;font-size:12px;color:var(--dim);word-break:break-all}}
  footer{{text-align:center;color:var(--dim);padding:24px;font-size:11px;border-top:1px solid var(--border);margin-top:40px;letter-spacing:1px}}
  .about{{background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--accent2);border-radius:10px;padding:18px 22px;margin-top:40px}}
  .about h3{{margin:0 0 10px;color:var(--accent2);font-size:14px;letter-spacing:1.5px;text-transform:uppercase}}
  .about p{{margin:6px 0;font-size:13px;color:var(--dim)}}
  .about b{{color:var(--text)}}
</style></head><body>

<header>
  <div class="brand">
    <h1>⚔ {a['tool']}</h1>
    <div class="sub">v{r['version']} · Hardened Web Security Audit</div>
  </div>
  <div class="chip">RUN {r['run_id']}</div>
</header>

<main>

<section class="cat">
<h2>Target</h2>
<div class="info-grid">
  <div class="info-card"><div class="k">Target</div><div class="v">{_html_escape(r['target'])}</div></div>
  <div class="info-card"><div class="k">Timestamp</div><div class="v">{r['timestamp']}</div></div>
  <div class="info-card"><div class="k">Total Findings</div><div class="v">{len(r['findings'])}</div></div>
  <div class="info-card"><div class="k">Evidence Files</div><div class="v">{len(r.get('evidence_files', []))}</div></div>
</div>
</section>

<section class="cat">
<h2>Executive Summary</h2>
<div class="scards">{summary_cards}</div>
</section>

{layers_html}

<section class="cat">
<h2>Assets</h2>
<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>{asset_rows}</tbody></table>
</section>

<section class="cat">
<h2>TLS</h2>
<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>{tls_rows or '<tr><td colspan=2>No TLS data</td></tr>'}</tbody></table>
</section>

<section class="cat">
<h2>DNS</h2>
<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>{dns_rows or '<tr><td colspan=2>No DNS data</td></tr>'}</tbody></table>
</section>

{cat_sections}

<div class="about">
  <h3>About</h3>
  <p><b>Tool:</b> {a['tool']} v{r['version']}</p>
  <p><b>Author:</b> {a['name']} — {a['country']}</p>
  <p><b>Contact:</b> {a['email']}</p>
  <p><b>Purpose:</b> Authorized web security auditing. Detects header/TLS/DNS/dependency/content-security issues. Use only on assets you own or have written permission to test.</p>
</div>

</main>
<footer>{a['tool']} v{r['version']} · {a['name']} · {a['country']}</footer>
</body></html>"""


def _layer_pill(difficulty):
    d = (difficulty or "").upper()
    if d in ("HARD",):
        return "hard"
    if d in ("MEDIUM", "STANDARD"):
        return "standard"
    if d in ("EASY",):
        return "easy"
    if d in ("OPEN", "NONE"):
        return "open"
    return "unknown"


# ============================================================
# HISTORY MANAGER
# ============================================================
class HistoryManager:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def load(self):
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def clear(self):
        try:
            if os.path.exists(self.path):
                os.remove(self.path)
        except Exception:
            pass

    def show(self):
        entries = self.load()
        if not entries:
            print(f"{C.Y}No scan history yet.{C.W}")
            return
        print(f"\n{C.CY}┌─ SCAN HISTORY ({len(entries)}) ──────────────────────────────┐{C.W}")
        for i, e in enumerate(reversed(entries[-30:]), 1):
            sev = e.get("summary", {})
            total = e.get("total", 0)
            c = sev.get("critical", 0); h = sev.get("high", 0)
            m = sev.get("medium", 0); lo = sev.get("low", 0)
            print(f"{C.CY}│{C.W} [{i:02d}] {C.BOLD}{e.get('target','?')}{C.W}")
            print(f"{C.CY}│{C.W}      Run: {e.get('run_id','?')} | Time: {e.get('timestamp','?')}")
            print(f"{C.CY}│{C.W}      Findings: {total} (Crit:{c} High:{h} Med:{m} Low:{lo})")
            print(f"{C.CY}│{C.W}      Report: {e.get('html','n/a')}")
            print(f"{C.CY}│{C.W}")
        print(f"{C.CY}└──────────────────────────────────────────────────────┘{C.W}")

        try:
            pick = input(f"{C.BOLD}Open a report by number (or Enter to go back): {C.W}").strip()
            if pick.isdigit():
                idx = int(pick) - 1
                rev = list(reversed(entries[-30:]))
                if 0 <= idx < len(rev):
                    path = rev[idx].get("html")
                    if path and os.path.exists(path):
                        open_report(path)
                    else:
                        print(f"{C.R}Report file not found: {path}{C.W}")
        except (EOFError, KeyboardInterrupt):
            pass


# ============================================================
# REPORT OPENER
# ============================================================
def open_report(path):
    """Open HTML report in browser / webview, cross-platform."""
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        print(f"{C.R}❌ File not found: {abs_path}{C.W}")
        return False

    uri = "file://" + abs_path
    try:
        if shutil.which("termux-open"):
            subprocess.Popen(["termux-open", abs_path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{C.G}✓ Opened in Termux viewer.{C.W}")
            return True
        if platform.system() == "Darwin" and shutil.which("open"):
            subprocess.Popen(["open", abs_path])
            return True
        if platform.system() == "Windows":
            os.startfile(abs_path)  # type: ignore
            return True
        if shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", abs_path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        if webbrowser.open(uri):
            return True
    except Exception as e:
        print(f"{C.Y}⚠ Default open failed: {e}{C.W}")

    print(f"{C.Y}Open manually: file://{abs_path}{C.W}")
    return False


def prompt_open(path):
    try:
        ans = input(f"\n{C.BOLD}Open web [y/n]? {C.W}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if ans in ("y", "yes"):
        open_report(path)


# ============================================================
# CORE ENGINE
# ============================================================
class CoreEngine:
    def __init__(self, config):
        self.config = config
        self.scope = ScopeManager(config)
        self.evidence = EvidenceCollector(config)
        self.http = HTTPAnalyzer(config, self.scope, self.evidence)
        self.tls = TLSAnalyzer(config["scan"]["timeout"])
        self.dns = DNSAnalyzer()
        self.assets_dc = AssetDiscovery(self.http)
        self.detector = VulnerabilityDetector()
        self.reporter = ReportEngine(config["reporting"]["output_dir"])

    def run(self, url):
        parsed = urlparse(url)
        self.scope.set_target(url)
        print(f"{C.G}✅ Scope OK: {parsed.hostname}{C.W}")

        layers = []

        print(f"\n{C.CY}[*] Probing security layers (military + deception mode)...{C.W}")
        http_result = self.http.fetch(url)
        if "error" in http_result:
            print(f"{C.R}❌ {http_result['error']}{C.W}")
            return None

        layer = http_result.get("layer", {})
        if layer:
            layers.append(layer)
            lc = {"HARD": C.R, "MEDIUM": C.Y, "EASY": C.G, "OPEN": C.G}.get(layer.get("difficulty", "UNKNOWN"), C.W)
            print(f"   {lc}Layer: {layer.get('name')} ({layer.get('difficulty')}) — {http_result['attempts']} attempt(s){C.W}")

        print(f"   {C.G}Status: {http_result['status']}  Time: {http_result['elapsed']:.2f}s{C.W}")
        print(f"   {C.G}Evidence: {http_result['evidence_file']}{C.W}")

        tls_findings, tls_info = [], {}
        if url.startswith("https"):
            print(f"\n{C.CY}[*] TLS Analysis...{C.W}")
            tls = self.tls.analyze(url)
            tls_findings = tls["findings"]
            tls_info = tls["info"]
            print(f"   {C.G}TLS: {tls_info.get('tls_version', 'N/A')}{C.W}")
            if "cert_expiry_days" in tls_info:
                print(f"   {C.G}Cert expires in: {tls_info['cert_expiry_days']} days{C.W}")

        print(f"\n{C.CY}[*] DNS Security Analyzer...{C.W}")
        dns = self.dns.analyze(url)
        dns_findings = dns["findings"]
        dns_info = dns["info"]
        print(f"   {C.G}A: {dns_info.get('A') or 'n/a'}")
        print(f"   {C.G}SPF: {'✓' if dns_info.get('SPF') else '✗'}  DMARC: {'✓' if dns_info.get('DMARC') else '✗'}  DNSSEC: {'✓' if dns_info.get('DNSSEC_enabled') else '✗'}{C.W}")

        assets = self.assets_dc.discover(http_result)

        print(f"\n{C.CY}[*] Vulnerability Detection...{C.W}")
        all_findings = list(tls_findings) + list(dns_findings)
        all_findings.extend(self.detector.run(http_result, assets=assets, analyzer=self.http))

        # Attempt a few security-layer probes on sensitive paths
        print(f"\n{C.CY}[*] Multi-layer attack surface probe...{C.W}")
        probe_paths = ["/admin", "/wp-admin", "/.env", "/api", "/login"]
        for p in probe_paths[:5]:
            try:
                purl = (http_result.get("final_url") or url).rstrip("/") + p
                pr = self.http.fetch(purl)
                if "error" in pr:
                    continue
                pr_layer = pr.get("layer", {})
                if pr_layer and pr_layer.get("layer") not in ("NONE", "REDIRECT"):
                    if pr_layer not in layers:
                        layers.append(pr_layer)
                        lc = {"HARD": C.R, "MEDIUM": C.Y, "EASY": C.G}.get(pr_layer.get("difficulty", "UNKNOWN"), C.W)
                        print(f"   {lc}{p}: {pr_layer.get('name')} ({pr_layer.get('difficulty')}){C.W}")
            except Exception:
                pass

        diff_summary = {"HARD": 0, "MEDIUM": 0, "EASY": 0, "OPEN": 0, "UNKNOWN": 0}
        for l in layers:
            d = l.get("difficulty", "UNKNOWN")
            diff_summary[d] = diff_summary.get(d, 0) + 1
        print(f"\n   {C.BOLD}Security layers: {len(layers)} total")
        print(f"   {C.R}HARD: {diff_summary['HARD']}{C.W}  "
              f"{C.Y}STANDARD: {diff_summary['MEDIUM']}{C.W}  "
              f"{C.G}EASY: {diff_summary['EASY']}{C.W}  "
              f"{C.CY}OPEN: {diff_summary['OPEN']}{C.W}")

        print(f"\n{C.CY}[*] Generating report...{C.W}")
        result = self.reporter.generate(
            url, all_findings,
            metadata={
                "http_status": http_result["status"],
                "final_url": http_result["final_url"],
                "attempts": http_result.get("attempts", 1),
                "assets": {
                    "links": len(assets["links"]),
                    "forms": len(assets["forms"]),
                    "scripts": len(assets["scripts"]),
                    "api_endpoints": len(assets["api_endpoints"]),
                    "has_robots": bool(assets["robots"]),
                    "has_sitemap": bool(assets["sitemap"]),
                    "tech": ", ".join(assets["tech"]) or "n/a",
                    "external_domains": ", ".join(assets["external_domains"][:8]) or "n/a",
                },
                "tls": tls_info,
                "dns": dns_info,
                "layers": layers,
            },
            evidence_files=self.evidence.files,
        )

        print(f"\n{C.BOLD}{C.CY}{'═' * 58}{C.W}")
        print(f"{C.BOLD}{C.G}✅ SCAN COMPLETED{C.W}")
        print(f"{C.CY}{'═' * 58}{C.W}")
        for sev, count in result["summary"].items():
            color = {"critical": C.R, "high": C.M, "medium": C.Y, "low": C.G, "info": C.CY}.get(sev, C.W)
            print(f"  {color}● {sev.upper():8}{C.W} : {count}")
        print(f"\n{C.G}📄 Report: {result['html']}{C.W}")
        print(f"{C.DIM}   JSON : {result['json']}")
        print(f"   TXT  : {result['txt']}{C.W}")

        prompt_open(result["html"])
        return result


# ============================================================
# ABOUT MENU
# ============================================================
def show_about():
    a = CONFIG["author"]
    print(f"""
{C.CY}┌──────────────────────────────────────────────────┐
│               ABOUT — {a['tool']} {a['version']}                │
├──────────────────────────────────────────────────┤
│  Name    : {a['name']}
│  Country : {a['country']}
│  Email   : {a['email']}
├──────────────────────────────────────────────────┤
│  Capabilities
│    • Security headers, CSP, CORS, cookie, session
│    • TLS version / cipher / cert expiry / issuer
│    • DNS: A/AAAA/MX/NS/TXT, SPF, DMARC, DNSSEC, CAA
│    • Sensitive-path exposure (.git, .env, backups)
│    • Dependency version detection + known CVEs
│    • 5-layer security probing (military + deception)
│    • Multi-tactical retry engine (up to 5 attempts)
│    • HTML / JSON / TXT reports with evidence
├──────────────────────────────────────────────────┤
│  Legal
│    Use only on assets you own or have written
│    authorization to test. Author not responsible
│    for misuse.
└──────────────────────────────────────────────────┘{C.W}
""")


# ============================================================
# MENU
# ============================================================
def menu():
    while True:
        clear()
        print(BANNER)
        print(f"{C.CY}┌────────────── MAIN MENU ──────────────┐{C.W}")
        print(f"{C.CY}│{C.W}  {C.BOLD}1{C.W}  ⚔  Scan target")
        print(f"{C.CY}│{C.W}  {C.BOLD}2{C.W}  ⚡  Quick scan (headers + TLS + DNS)")
        print(f"{C.CY}│{C.W}  {C.BOLD}3{C.W}  📜  History")
        print(f"{C.CY}│{C.W}  {C.BOLD}4{C.W}  ℹ  About")
        print(f"{C.CY}│{C.W}  {C.BOLD}5{C.W}  ✕  Exit")
        print(f"{C.CY}└──────────────────────────────────────┘{C.W}")

        try:
            choice = input(f"{C.BOLD}▸ Select [1-5]: {C.W}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice in ("1", "2"):
            try:
                url = input(f"{C.BOLD}🔗 Target URL: {C.W}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not url:
                print(f"{C.R}❌ No URL entered.{C.W}")
                time.sleep(1)
                continue
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            if not urlparse(url).hostname:
                print(f"{C.R}❌ Invalid URL.{C.W}")
                time.sleep(1)
                continue
            if choice == "1":
                engine = CoreEngine(CONFIG)
                res = engine.run(url)
                if res is None:
                    print(f"{C.R}Scan failed.{C.W}")
            else:
                quick_scan(url)
            input(f"\n{C.DIM}Press Enter to return to menu...{C.W}")
        elif choice == "3":
            clear()
            print(BANNER)
            HistoryManager(CONFIG["history_file"]).show()
            input(f"\n{C.DIM}Press Enter...{C.W}")
        elif choice == "4":
            clear()
            print(BANNER)
            show_about()
            input(f"\n{C.DIM}Press Enter...{C.W}")
        elif choice == "5":
            print(f"{C.G}Bye. Stay legal.{C.W}")
            return
        else:
            print(f"{C.Y}Invalid choice.{C.W}")
            time.sleep(0.6)


def quick_scan(url):
    print(f"\n{C.CY}[*] Quick scan: {url}{C.W}")
    scope = ScopeManager(CONFIG)
    ev = EvidenceCollector(CONFIG)
    http = HTTPAnalyzer(CONFIG, scope, ev)
    scope.set_target(url)
    findings = []
    h = http.fetch(url)
    if "error" in h:
        print(f"{C.R}{h['error']}{C.W}")
        return
    findings.extend(module_security_headers(h))
    findings.extend(module_info_disclosure(h))
    findings.extend(module_cookies(h))
    findings.extend(module_cors(h))
    if url.startswith("https"):
        findings.extend(TLSAnalyzer().analyze(url)["findings"])
    findings.extend(DNSAnalyzer().analyze(url)["findings"])
    rep = ReportEngine(CONFIG["reporting"]["output_dir"])
    res = rep.generate(url, findings, metadata={"mode": "quick"})
    print(f"{C.G}✓ Quick report: {res['html']}{C.W}")
    prompt_open(res["html"])


# ============================================================
# MAIN
# ============================================================
def main():
    url = None
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if arg.lower() in ("-a", "--about"):
            print(BANNER)
            show_about()
            return
        if arg.lower() in ("-h", "--help"):
            print(f"Usage: python {os.path.basename(sys.argv[0])} <url>")
            print(f"       python {os.path.basename(sys.argv[0])} --about")
            return
        url = arg

    if not url:
        menu()
        return

    print(BANNER)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not urlparse(url).hostname:
        print(f"{C.R}❌ Invalid URL: {url}{C.W}")
        sys.exit(1)

    print(f"{C.CY}▶ Target: {url}{C.W}")
    print(f"{C.CY}▶ Host  : {urlparse(url).hostname}{C.W}")

    engine = CoreEngine(CONFIG)
    result = engine.run(url)
    if result is None:
        sys.exit(3)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.R}Interrupted by user.{C.W}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{C.R}❌ Fatal: {e}{C.W}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
