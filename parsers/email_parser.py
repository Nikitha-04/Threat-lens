import email
import hashlib
import os
import re
from email.header import decode_header, make_header
from email.utils import parseaddr, getaddresses
from urllib.parse import urlparse, parse_qsl, urlencode
from bs4 import BeautifulSoup

TRACKING_PARAM_PREFIXES = ("utm_",)
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "twclid", "yclid", "igshid",
    "wbraid", "gbraid", "mc_cid", "mc_eid", "_hsenc", "_hsmi", "mkt_tok",
    "ref", "ref_src", "source", "campaign"
}

def decode_rfc2047(header_val):
    if not header_val:
        return ""
    try:
        return str(make_header(decode_header(header_val))).strip()
    except Exception:
        return str(header_val).strip()

def sanitize_filename(filename):
    if not filename:
        return "unnamed"
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)

def extract_safe_message_id(raw_bytes: bytes) -> str:
    """Quickly extract sanitized message_id from raw email bytes without full parsing."""
    try:
        msg = email.message_from_bytes(raw_bytes)
        mid = msg.get("Message-ID", "")
        if mid:
            safe = sanitize_filename(mid.strip("<>"))
            if safe and safe != "unnamed":
                return safe
    except Exception:
        pass
    return hashlib.sha256(raw_bytes).hexdigest()

def normalize_url_for_dedup(url: str) -> tuple[str, str, str]:
    """
    Returns (domain, path, filtered_query) for deduplicating URLs.
    Tracking query parameters (utm_*, fbclid, etc.) are omitted.
    """
    try:
        p = urlparse(url.strip())
        domain = p.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        path = p.path.rstrip('/')

        filtered_q = []
        if p.query:
            for k, v in parse_qsl(p.query, keep_blank_values=True):
                k_lower = k.lower()
                if k_lower in TRACKING_PARAMS or any(k_lower.startswith(prefix) for prefix in TRACKING_PARAM_PREFIXES):
                    continue
                filtered_q.append((k_lower, v))
        filtered_q.sort()
        return (domain, path, urlencode(filtered_q))
    except Exception:
        return (url.strip().lower(), "", "")

def deduplicate_links(links: list[str]) -> list[str]:
    """
    Deduplicate links per email (same URL, and same domain+path ignoring tracking query parameters).
    Preserves order of first appearance.
    """
    seen_exact = set()
    seen_keys = set()
    deduped = []
    for link in links:
        if not isinstance(link, str) or not link.strip():
            continue
        cleaned = link.strip()
        if cleaned in seen_exact:
            continue
        seen_exact.add(cleaned)

        key = normalize_url_for_dedup(cleaned)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(cleaned)
    return deduped

def extract_links(text, html):
    extracted = []
    if html:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                if href.lower().startswith(('http://', 'https://')):
                    extracted.append(href)
        except Exception:
            pass
    
    if text:
        url_pattern = re.compile(r'(?:https?://|www\.)[^\s<>\[\]\(\)"\']+')
        found = url_pattern.findall(text)
        for url in found:
            url = url.rstrip(".,;!?)]}")
            extracted.append(url)
            
    # Normalize protocol & www for deduplication
    normalized_list = []
    for url in extracted:
        # Standardize for unique comparisons
        normalized_list.append(url)

    # First round of deduplication: handle www vs https variants
    unique_links = {}
    for url in normalized_list:
        comp = url.lower()
        if comp.startswith("http://"): comp = comp[7:]
        elif comp.startswith("https://"): comp = comp[8:]
        if comp.startswith("www."): comp = comp[4:]
        comp = comp.rstrip('/')

        if comp not in unique_links:
            unique_links[comp] = url
        else:
            existing = unique_links[comp]
            if url.startswith("https://") and not existing.startswith("https://"):
                unique_links[comp] = url
            elif url.startswith("http://") and existing.startswith("www."):
                unique_links[comp] = url

    # Apply tracking-query and domain+path deduplication
    return deduplicate_links(list(unique_links.values()))

def parse_email(raw_bytes: bytes, attachments_dir="./data/attachments"):
    msg = email.message_from_bytes(raw_bytes)
    
    message_id = msg.get("Message-ID", "")
    if message_id:
        message_id = message_id.strip("<>")
    else:
        message_id = hashlib.sha256(raw_bytes).hexdigest()
        
    safe_message_id = sanitize_filename(message_id)
    
    raw_headers = {}
    received_chain = []
    
    for key, val in msg.items():
        if key.lower() == "received":
            received_chain.append(val)
            
        if key in raw_headers:
            if isinstance(raw_headers[key], list):
                raw_headers[key].append(val)
            else:
                raw_headers[key] = [raw_headers[key], val]
        else:
            raw_headers[key] = val
            
    from_name, from_email = parseaddr(msg.get("From", ""))
    to_list = [{"name": n, "email": e} for n, e in getaddresses(msg.get_all("To", []))]
    
    body_text = ""
    body_html = None
    attachments = []
    
    msg_attach_dir = os.path.join(attachments_dir, safe_message_id)
    
    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition"))
        
        if part.is_multipart():
            continue
            
        if content_type == 'text/plain' and 'attachment' not in disposition:
            try:
                body_text += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
            except Exception:
                pass
        elif content_type == 'text/html' and 'attachment' not in disposition:
            try:
                html_part = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                body_html = (body_html or "") + html_part
            except Exception:
                pass
        else:
            filename = part.get_filename()
            if filename:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                
                os.makedirs(msg_attach_dir, exist_ok=True)
                safe_filename = sanitize_filename(filename)
                save_path = os.path.normpath(os.path.join(msg_attach_dir, safe_filename))
                
                with open(save_path, "wb") as f:
                    f.write(payload)
                    
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "saved_path": save_path
                })
                
    result = {
        "message_id": message_id,
        "date": msg.get("Date"),
        "from": {"name": from_name, "email": from_email},
        "to": to_list,
        "reply_to": msg.get("Reply-To"),
        "subject": decode_rfc2047(msg.get("Subject", "")),
        "raw_headers": raw_headers,
        "received_chain": received_chain,
        "body_text": body_text.strip(),
        "body_html": body_html,
        "links": extract_links(body_text, body_html),
        "attachments": attachments
    }
    
    return result
