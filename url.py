import os
import re
import sqlite3
from urllib.parse import urlparse, urlunparse

# -----------------------
# DB + URL helpers
# -----------------------
def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), "whitelist.db")
    conn = sqlite3.connect(db_path)
    # logger.info(f"Whitelist DB path: {db_path}")
    return conn

url_pattern = re.compile(r'https?://[^\s<>"\']+|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b|\S+@\S+')

def extract_domains(text):
    """Return list of domain strings extracted from text (lowercased, no www)."""
    tokens = url_pattern.findall(text)
    domains = []
    for t in tokens:
        t = t.strip()
        # If it's a full URL, parse host, else treat as bare domain/email
        if t.lower().startswith("http://") or t.lower().startswith("https://") or t.lower().startswith("www."):
            try:
                parsed = urlparse(t if "://" in t else "http://" + t)
                host = parsed.netloc.lower().split(':')[0]
                if host.startswith("www."):
                    host = host[4:]
                domains.append(host)
            except Exception:
                continue
        else:
            # email or bare domain
            if "@" in t:
                try:
                    host = t.split("@", 1)[1].lower().split(':')[0]
                    if host.startswith("www."):
                        host = host[4:]
                    domains.append(host)
                except Exception:
                    continue
            else:
                d = t.lower().strip().strip('/')
                if d.startswith("www."):
                    d = d[4:]
                if "." in d:
                    domains.append(d.split(':')[0])
    # dedupe, keep order
    return list(dict.fromkeys(domains))

def is_whitelisted(domains):
    """
    Return True if any domain in `domains` is whitelisted.
    Matching rules:
      - exact match: domain == whitelist_entry
      - suffix match: domain endswith '.' + whitelist_entry
        (so 'docs.google.com' matches 'google.com')
    """
    if not domains:
        return False

    # load whitelist into a set (lowercased)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT LOWER(domain) FROM whitelist")
        rows = cursor.fetchall()
        whitelist_set = {r[0] for r in rows if r and r[0]}
    finally:
        conn.close()

    for domain in domains:
        d = (domain or "").lower().strip().strip('/')
        if not d:
            continue
        # direct match
        if d in whitelist_set:
            return True
        # suffix match (allow subdomains)
        for wl in whitelist_set:
            if d == wl or d.endswith("." + wl):
                return True
    return False



# -----------------------
# Blacklist helpers
# -----------------------
def get_blacklist_connection():
    db_path = os.path.join(os.path.dirname(__file__), "blacklist.db")
    conn = sqlite3.connect(db_path)
    # logger.info(f"Blacklist DB path: {db_path}")
    return conn

def normalize_full_url(raw_url: str) -> str:
    """Normalize a URL for matching while preserving query and fragment.
    (If you prefer to strip query/fragment, revert to your previous version.)
    """
    try:
        if not raw_url:
            return ""
        # ensure scheme for parsing
        if "://" not in raw_url:
            raw_url = "http://" + raw_url
        p = urlparse(raw_url)
        scheme = p.scheme.lower()
        netloc = p.netloc.lower().rstrip('/')
        path = p.path.rstrip('/')
        query = p.query  # preserve query
        fragment = p.fragment  # preserve fragment
        # Rebuild including query and fragment
        normalized = urlunparse((scheme, netloc, path, "", query, fragment))
        return normalized
    except Exception:
        return raw_url.strip().lower().rstrip('/')

def extract_urls_and_domains(text: str):
    """
    Return two lists: full_urls (as extracted, preserving query/fragment) and domains (hostnames).
    Uses `url_pattern` to find tokens.
    """
    found = url_pattern.findall(text)
    tokens = []
    for f in found:
        if isinstance(f, tuple):
            t = "".join(f).strip()
            if t:
                tokens.append(t)
        else:
            tokens.append(f.strip())

    full_urls = []
    domains = []
    for token in tokens:
        if token.lower().startswith("http://") or token.lower().startswith("https://") or token.lower().startswith("www."):
            # keep the whole URL (including query + fragment)
            full_urls.append(token)
            # extract domain
            try:
                parsed = urlparse(token if "://" in token else "http://" + token)
                host = parsed.netloc.lower().split(':')[0]
                if host.startswith("www."):
                    host = host[4:]
                domains.append(host)
            except Exception:
                pass
        else:
            # bare domain/email
            if "@" in token:
                try:
                    domain_part = token.split("@", 1)[1].lower().strip().strip('/')
                    if domain_part.startswith("www."):
                        domain_part = domain_part[4:]
                    domains.append(domain_part.split(':')[0])
                except Exception:
                    pass
            else:
                tok = token.lower().strip().strip('/')
                if tok.startswith("www."):
                    tok = tok[4:]
                if "." in tok:
                    domains.append(tok.split(':')[0])

    # debug prints (optional)
    # logger.info(f"[DEBUG] Input text: {text}")
    # logger.info(f"[DEBUG] Extracted full URLs: {full_urls}")
    # logger.info(f"[DEBUG] Extracted domains: {domains}")

    return list(dict.fromkeys(full_urls)), list(dict.fromkeys(domains))


def is_blacklisted(text: str):
    """
    Returns (bool, reason_str) — True + reason if any URL/domain in text matches blacklist.db.
    """
    try:
        full_urls, domains = extract_urls_and_domains(text)
        if not full_urls and not domains:
            # logger.info("[DEBUG] No URLs or domains extracted.")
            return False, None

        conn = get_blacklist_connection()
        cursor = conn.cursor()

        # 1) check normalized full URLs
        for u in full_urls:
            # logger.info(f"[DEBUG] Checking full URL against DB: {u}")
            cursor.execute("SELECT url FROM blacklist WHERE LOWER(url) = ?", (u.lower(),))
            row = cursor.fetchone()
            if row:
                # logger.info(f"[DEBUG] FULL URL matched blacklist → {row[0]}")
                conn.close()
                return True, f"Blacklisted URL matched: {u}"

        # 2) check domain exact matches
        for d in domains:
            # logger.info(f"[DEBUG] Checking domain against DB: {d}")
            cursor.execute("SELECT url FROM blacklist WHERE LOWER(url) = ? OR LOWER(url) = ?", (d.lower(), f"www.{d}".lower()))
            row = cursor.fetchone()
            if row:
                # logger.info(f"[DEBUG] DOMAIN matched blacklist → {row[0]}")
                conn.close()
                return True, f"Blacklisted domain matched: {d}"

        # 3) fallback substring check
        for d in domains:
            like_pattern = f"%{d.lower()}%"
            # logger.info(f"[DEBUG] Checking substring match for domain: {d} ({like_pattern})")
            cursor.execute("SELECT url FROM blacklist WHERE LOWER(url) LIKE ? LIMIT 1", (like_pattern,))
            row = cursor.fetchone()
            if row:
                # logger.info(f"[DEBUG] SUBSTRING matched blacklist → {row[0]}")
                conn.close()
                return True, f"Blacklisted domain substring matched in URL for: {d}"

        conn.close()
        # logger.info("[DEBUG] No blacklist match found.")
        return False, None
    except Exception as e:
        return False, None



# -----------------------
# URL masking for safe translation
# -----------------------
# This pattern matches:
#  - full URLs starting with http(s):// or www.
#  - bare domains like example.com
#  - email addresses
URL_PATTERN = re.compile(
    r'((?:https?://|http://|www\.)\S+|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b|\S+@\S+)'
)

def mask_urls(text: str):
    """Replace found URLs/domains/emails with placeholders and return (masked_text, mapping)."""
    found = URL_PATTERN.findall(text)
    mapping = {}
    masked = text
    # sort by length desc to avoid partial overlaps when replacing
    for i, original in enumerate(sorted(set(found), key=lambda s: -len(s))):
        placeholder = f"__URL_{i}__"
        mapping[placeholder] = original
        # use replace (safe after sorting by length)
        masked = masked.replace(original, placeholder)
    return masked, mapping

def restore_placeholders(text: str, mapping: dict):
    """Restore placeholders back to original strings."""
    for placeholder, original in mapping.items():
        text = text.replace(placeholder, original)
    return text