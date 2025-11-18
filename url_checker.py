import sys
from urllib.parse import urlparse
import re

SUSPICIOUS_TLDS = {'.zip', '.kim', '.country', '.stream', '.ru', '.cn', '.tk', '.gq', '.ml'}

def host_is_ip(host):
    if not host:
        return False
    if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
        return True
    if host.startswith('[') and host.endswith(']'):
        return True
    return False

def contains_punycode(host):
    if not host:
        return False
    return host.startswith('xn--') or 'xn--' in host

def suspicious_tld(host):
    if not host:
        return False, None
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return True, tld
    return False, None

def subdomain_count(host):
    if not host:
        return 0
    parts = host.split('.')
    return max(0, len(parts)-2)

def check(url):
    reasons = []
    try:
        parsed = urlparse(url)
    except Exception as e:
        print("Invalid URL:", e)
        return

    host = parsed.hostname or ''
    path = parsed.path or ''
    full = url

    if host in ("127.0.0.1", "localhost", "::1"):
      print("Verdict: NO OBVIOUS ISSUES")
      return
    if '@' in full:
        reasons.append("URL contains '@' which may obfuscate the true host.")
    if not host:
        reasons.append("No hostname detected in URL.")
    if host and host_is_ip(host):
        reasons.append("Hostname is an IP address.")
    if host and contains_punycode(host):
        reasons.append("Hostname contains punycode (xn--).")
    is_susp, tld = suspicious_tld(host)
    if is_susp:
        reasons.append(f"Hostname ends with suspicious TLD '{tld}'.")
    if len(full) > 120:
        reasons.append("URL unusually long (>120 chars).")
    if subdomain_count(host) >= 3:
        reasons.append("Many subdomains which could be a sign of trying to hide the real domain.")
    if re.search(r'login|signin|account|verify|update|confirm', path, re.IGNORECASE):
        reasons.append("Path includes login/verify keywords which is common in phishing landing URLs.")
    if host and re.search(r'paypal|google|microsoft|amazon|icloud|bank', host, re.IGNORECASE):
        reasons.append("Hostname mentions a high-profile brand. So verify legitimacy first.")

    if reasons:
        print("Verdict: SUSPICIOUS")
        print("Reasons:")
        for r in reasons:
            print(" -", r)
    else:
        print("Verdict: NO OBVIOUS ISSUES")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python url_checker.py '<url>'")
        sys.exit(2)
    check(sys.argv[1])
