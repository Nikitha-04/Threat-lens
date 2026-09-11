import email
import hashlib
import os
import re
from email.utils import parseaddr, getaddresses
from bs4 import BeautifulSoup

def sanitize_filename(filename):
    if not filename:
        return "unnamed"
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)

def extract_links(text, html):
    extracted = set()
    if html:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                extracted.add(a['href'])
        except Exception:
            pass
    
    if text:
        url_pattern = re.compile(r'(?:https?://|www\.)[^\s<>\[\]\(\)"\']+')
        found = url_pattern.findall(text)
        for url in found:
            url = url.rstrip(".,;!?)]}")
            extracted.add(url)
            
    unique_links = {}
    for url in extracted:
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
                
    return sorted(list(unique_links.values()))

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
        "subject": msg.get("Subject", ""),
        "raw_headers": raw_headers,
        "received_chain": received_chain,
        "body_text": body_text.strip(),
        "body_html": body_html,
        "links": extract_links(body_text, body_html),
        "attachments": attachments
    }
    
    return result
