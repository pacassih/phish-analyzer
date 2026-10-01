#!/usr/bin/env python3
"""Phishing email analyzer.

Parses .eml files and produces a 0-100 risk score from weighted heuristics:

    Authentication ..... SPF / DKIM / DMARC results            (up to 40 pts)
    Sender mismatch .... Reply-To / Return-Path vs From domain (up to 20 pts)
    Lookalike domains .. typosquat of well-known brands        (20 pts)
    Content tricks ..... urgency language, URL shorteners,
                         display-text vs href mismatch         (up to 40 pts)
    Attachments ........ risky file types                     (15 pts)

Every point is explained: the output lists each triggered reason, the
defanged URLs found, attachment SHA256 hashes, and the raw
Authentication-Results. A Markdown report can be written for documentation.

Usage:
    python analyze_phish.py samples/benign.eml
    python analyze_phish.py samples/*.eml --report phishing_report.md
"""

from __future__ import annotations

import argparse
import email
import hashlib
import os
import re
from email import policy
from email.message import Message
from html.parser import HTMLParser
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Heuristic data
# ---------------------------------------------------------------------------

BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "bankofamerica",
    "chase", "wellsfargo", "netflix", "linkedin", "facebook", "instagram",
    "dhl", "fedex", "ups", "irs",
]

# Common affixes phishers bolt onto a typosquatted brand:
# "paypa1-secure.com", "micorsoft-verify.com", ...
AFFIXES = [
    "verify", "secure", "login", "account", "accounts", "support", "service",
    "online", "update", "alert", "auth", "signin", "billing", "security",
    "help", "center",
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "within 24 hours", "suspended", "act now",
    "final notice", "expires today", "account closure", "verify immediately",
    "limited time",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
}

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar",
    ".msi", ".com", ".pif", ".zip", ".rar", ".7z", ".iso", ".lnk",
}

URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_eml(path: str) -> Message:
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)


def domain_of(address: str | None) -> str:
    """Extract the domain from an email address header value."""
    match = re.search(r"@([\w.\-]+)", address or "")
    return match.group(1).lower().rstrip(".") if match else ""


def host_of(url: str) -> str:
    return urlparse(url).netloc.lower().split(":")[0]


def defang(url: str) -> str:
    """Render a URL safe to paste into reports / chat."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def get_text_parts(msg: Message) -> list[tuple[str, str]]:
    """Return (content_type, decoded_text) for every text part."""
    parts = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        parts.append((ctype, payload.decode(charset, errors="replace")))
    return parts


class LinkExtractor(HTMLParser):
    """Collect (href, display_text) pairs from <a> tags."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str | None, str]] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._buf = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None


def extract_urls(msg: Message) -> tuple[list[str], list[tuple[str, str]]]:
    """Return (plain-text urls, html (href, display_text) links)."""
    urls: list[str] = []
    html_links: list[tuple[str, str]] = []
    for ctype, text in get_text_parts(msg):
        if ctype == "text/html":
            extractor = LinkExtractor()
            extractor.feed(text)
            html_links.extend(
                (href, display) for href, display in extractor.links if href
            )
        else:
            urls.extend(URL_RE.findall(text))
    # De-duplicate while preserving order.
    urls = list(dict.fromkeys(urls))
    return urls, html_links


def get_attachments(msg: Message) -> list[dict]:
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
    return attachments


def parse_auth_results(msg: Message) -> dict[str, str]:
    """Pull spf/dkim/dmarc verdicts out of Authentication-Results."""
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    raw = str(msg.get("Authentication-Results", ""))
    for mech in results:
        match = re.search(rf"{mech}=(\w+)", raw, re.IGNORECASE)
        if match:
            results[mech] = match.group(1).lower()
    return results


# ---------------------------------------------------------------------------
# Typosquat detection
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def strip_affixes(label: str) -> str:
    """Remove phisher affixes so 'paypa1-secure' -> 'paypa1'."""
    changed = True
    while changed:
        changed = False
        for affix in AFFIXES:
            for sep in ("-", "_"):
                if label.startswith(affix + sep):
                    label = label[len(affix) + 1:]
                    changed = True
                elif label.endswith(sep + affix):
                    label = label[:-(len(affix) + 1)]
                    changed = True
    return label


def find_typosquat(domain: str) -> tuple[str, str] | None:
    """Return (brand, suspect_label) if a domain label is a near-miss of a
    well-known brand, else None."""
    labels = domain.split(".")
    check = labels[:-1] if len(labels) > 1 else labels  # skip the TLD
    for label in check:
        core = strip_affixes(label)
        for brand in BRANDS:
            if core == brand:
                continue  # exact brand match is not typosquat by itself
            if 1 <= levenshtein(core, brand) <= 2:
                return brand, label
    return None


def looks_like_url(text: str) -> bool:
    text = text.strip().lower()
    return bool(URL_RE.match(text) or text.startswith("www.")
                or re.match(r"^[\w.\-]+\.[a-z]{2,}(/.*)?$", text))


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def analyze(path: str) -> dict:
    msg = parse_eml(path)
    reasons: list[tuple[int, str]] = []
    score = 0

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append((points, reason))

    from_addr = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))
    subject = str(msg.get("Subject", ""))
    from_dom = domain_of(from_addr)

    auth = parse_auth_results(msg)

    # --- Authentication ----------------------------------------------------
    if auth["spf"] == "fail":
        add(15, "SPF authentication failed")
    elif auth["spf"] == "softfail":
        add(5, "SPF softfail - sending server not fully authorized")
    elif auth["spf"] == "none":
        add(3, "No SPF result published for this domain")
    if auth["dkim"] == "fail":
        add(10, "DKIM signature invalid")
    elif auth["dkim"] == "none":
        add(3, "No DKIM signature present")
    if auth["dmarc"] == "fail":
        add(15, "DMARC check failed")

    # --- Sender mismatch ----------------------------------------------------
    if reply_to and domain_of(reply_to) != from_dom:
        add(15, f"Reply-To domain ({domain_of(reply_to)}) differs from "
                f"From domain ({from_dom}) - replies go to the attacker")
    if return_path and domain_of(return_path) != from_dom:
        add(5, f"Return-Path domain ({domain_of(return_path)}) differs from "
               f"From domain ({from_dom})")

    # --- Lookalike domain ----------------------------------------------------
    if from_dom:
        typo = find_typosquat(from_dom)
        if typo:
            brand, label = typo
            add(20, f"From domain '{from_dom}' is a likely typosquat of "
                    f"'{brand}' (suspicious label: '{label}')")

    # --- Content tricks ------------------------------------------------------
    urls, html_links = extract_urls(msg)
    full_text = " ".join(text for _, text in get_text_parts(msg)).lower()
    hits = [kw for kw in URGENCY_KEYWORDS if kw in full_text]
    if hits:
        add(10, f"Urgency / threat language: {', '.join(hits)}")

    for url in urls:
        if host_of(url) in SHORTENERS:
            add(10, f"URL shortener hides the real destination: "
                    f"{defang(url)}")
            break

    for href, display in html_links:
        if display and looks_like_url(display) \
                and host_of(display) != host_of(href):
            add(20, f"Link text shows '{display.strip()}' but points to "
                    f"{defang(href)}")
            break

    # --- Attachments ----------------------------------------------------------
    attachments = get_attachments(msg)
    for att in attachments:
        ext = os.path.splitext(att["filename"])[1].lower()
        if ext in RISKY_EXTENSIONS:
            add(15, f"Risky attachment type: {att['filename']}")
            break

    score = min(score, 100)
    verdict = "HIGH RISK" if score >= 60 else "MEDIUM RISK" if score >= 30 \
        else "LOW RISK"

    return {
        "file": os.path.basename(path),
        "from": from_addr,
        "subject": subject,
        "auth": auth,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "urls": urls,
        "html_links": html_links,
        "attachments": attachments,
        "received_hops": len(msg.get_all("Received", [])),
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_result(r: dict) -> None:
    bar = "#" * (r["score"] // 5) + "-" * (20 - r["score"] // 5)
    print(f"\n{'=' * 70}\n{r['file']}\n{'=' * 70}")
    print(f"From:    {r['from']}")
    print(f"Subject: {r['subject']}")
    print(f"Score:   {r['score']}/100 [{bar}] {r['verdict']}")
    a = r["auth"]
    print(f"Auth:    SPF={a['spf']}  DKIM={a['dkim']}  DMARC={a['dmarc']}  "
          f"Received-hops={r['received_hops']}")
    print("\nReasons:")
    if r["reasons"]:
        for pts, reason in r["reasons"]:
            print(f"  +{pts:2d}  {reason}")
    else:
        print("  (none - no phishing indicators found)")
    print("\nURLs found (defanged):")
    seen = set()
    for url in r["urls"]:
        d = defang(url)
        if d not in seen:
            seen.add(d)
            print(f"  {d}")
    for href, display in r["html_links"]:
        print(f"  {defang(href)}   (displayed as: {display.strip()[:60]})")
    if not r["urls"] and not r["html_links"]:
        print("  (none)")
    print("\nAttachments:")
    if r["attachments"]:
        for att in r["attachments"]:
            print(f"  {att['filename']} ({att['size']} bytes)")
            print(f"    SHA256: {att['sha256']}")
    else:
        print("  (none)")


def write_report(path: str, results: list[dict]) -> None:
    lines = ["# Phishing Analysis Report", "",
             f"Analyzed {len(results)} message(s).", ""]
    for r in results:
        lines += [
            f"## {r['file']} - {r['score']}/100 ({r['verdict']})",
            "",
            f"- **From:** {r['from']}",
            f"- **Subject:** {r['subject']}",
            f"- **Authentication:** SPF={r['auth']['spf']}, "
            f"DKIM={r['auth']['dkim']}, DMARC={r['auth']['dmarc']}",
            "",
            "### Reasons",
            "",
        ]
        if r["reasons"]:
            lines += [f"- (+{pts}) {reason}" for pts, reason in r["reasons"]]
        else:
            lines.append("- No phishing indicators found.")
        lines += ["", "### URLs (defanged)", ""]
        urls = [defang(u) for u in r["urls"]]
        urls += [f"{defang(h)} (displayed as: {d.strip()[:60]})"
                 for h, d in r["html_links"]]
        lines += [f"- `{u}`" for u in urls] or ["- None"]
        lines += ["", "### Attachments", ""]
        if r["attachments"]:
            for att in r["attachments"]:
                lines += [f"- `{att['filename']}` ({att['size']} bytes)",
                          f"  - SHA256: `{att['sha256']}`"]
        else:
            lines.append("- None")
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\nMarkdown report written to {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze .eml files for phishing indicators.")
    parser.add_argument("eml", nargs="+", help=".eml file(s) to analyze")
    parser.add_argument("--report", default=None,
                        help="write a combined Markdown report to this path")
    args = parser.parse_args()

    results = [analyze(path) for path in args.eml]
    for r in results:
        print_result(r)
    if args.report:
        write_report(args.report, results)


if __name__ == "__main__":
    main()
