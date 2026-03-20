import re
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "password", "bank", "payment", "invoice", "confirm"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"
]


def extract_urls(text):
    if not text:
        return []

    pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    matches = re.findall(pattern, text)
    return list(set(matches))


def is_ip_address(hostname):
    if not hostname:
        return False

    ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    return re.match(ip_pattern, hostname) is not None


def get_verdict(score):
    if score >= 75:
        return "High Risk"
    elif score >= 50:
        return "Suspicious"
    elif score >= 25:
        return "Medium Risk"
    return "Low Risk"


def analyze_single_url(url):
    reasons = []
    score = 0

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    path = parsed.path.lower()

    extracted = tldextract.extract(hostname)
    domain = ".".join(part for part in [extracted.domain, extracted.suffix] if part)

    if is_ip_address(hostname.split(":")[0]):
        score += 25
        reasons.append("URL uses an IP address instead of a domain name")

    if len(url) > 75:
        score += 10
        reasons.append("URL is unusually long")

    if hostname.count(".") >= 3:
        score += 10
        reasons.append("URL contains many subdomains")

    if "--" in hostname or hostname.count("-") >= 2:
        score += 10
        reasons.append("Domain contains multiple hyphens")

    if "xn--" in hostname:
        score += 25
        reasons.append("Possible punycode/lookalike domain detected")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword found: {keyword}")

    if domain in SHORTENERS:
        score += 20
        reasons.append("URL shortener detected")

    if parsed.scheme == "http":
        score += 10
        reasons.append("Uses HTTP instead of HTTPS")

    verdict = get_verdict(score)

    return {
        "url": url,
        "score": score,
        "reasons": reasons,
        "verdict": verdict
    }


def analyze_urls(text):
    urls = extract_urls(text)
    return [analyze_single_url(url) for url in urls]