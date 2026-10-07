"""
forensics.py — Email header forensics and authentication analysis.
Analyzes SPF, DKIM, DMARC, alignment, red flags, and extracts originating IP.
"""
from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import re
import sys
from ipaddress import ip_address

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def _get_headers_list(raw_headers: dict, key_name: str) -> list[str]:
    """Retrieve all occurrences of a header, case-insensitively."""
    results = []
    for k, v in raw_headers.items():
        if k.lower() == key_name.lower():
            if isinstance(v, list):
                results.extend(v)
            elif isinstance(v, str):
                results.append(v)
    return results


def _extract_domain(email_str: str) -> str:
    """Extract domain portion from an email address."""
    if not email_str:
        return ""
    if "@" in email_str:
        return email_str.split("@")[-1].strip().lower().rstrip(">")
    return ""


def _is_public_ip(ip_str: str) -> bool:
    """Check if an IPv4 string is public."""
    try:
        ip = ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local)
    except ValueError:
        return False


def extract_originating_ip(raw_headers: dict, received_chain: list[str]) -> str | None:
    """
    Extract the most likely originating / client IP from email headers.
    Checks Received-SPF client-ip, Authentication-Results, and Received chain.
    """
    # 1. Check Received-SPF
    for r_spf in _get_headers_list(raw_headers, "Received-SPF"):
        match = re.search(r"client-ip=([0-9\.]+)", r_spf, re.IGNORECASE)
        if match and _is_public_ip(match.group(1)):
            return match.group(1)

    # 2. Check Authentication-Results for "designates X.X.X.X"
    for auth_hdr in _get_headers_list(raw_headers, "Authentication-Results") + _get_headers_list(raw_headers, "ARC-Authentication-Results"):
        match = re.search(r"designates\s+([0-9\.]+)", auth_hdr, re.IGNORECASE)
        if match and _is_public_ip(match.group(1)):
            return match.group(1)

    # 3. Check X-Originating-IP
    for x_ip in _get_headers_list(raw_headers, "X-Originating-IP"):
        clean_ip = x_ip.strip("[] \t\r\n")
        if _is_public_ip(clean_ip):
            return clean_ip

    # 4. Search Received chain from earliest (bottom) to newest (top)
    all_received = received_chain if received_chain else _get_headers_list(raw_headers, "Received")
    candidates = []
    for hop in all_received:
        found_ips = IP_PATTERN.findall(hop)
        for ip in found_ips:
            if _is_public_ip(ip):
                candidates.append(ip)

    if candidates:
        # Return the earliest public IP seen in the transport hops
        return candidates[-1]

    # Fallback: any found IP
    for hop in all_received:
        found_ips = IP_PATTERN.findall(hop)
        if found_ips:
            return found_ips[-1]

    return None


def analyze_forensics(parsed_data: dict) -> dict:
    """
    Analyze parsed email headers to extract forensic security data:
    SPF, DKIM, DMARC statuses, domain alignments, red flags, and originating IP.
    """
    raw_headers = parsed_data.get("raw_headers", {}) or {}
    received_chain = parsed_data.get("received_chain", []) or []

    message_id = parsed_data.get("message_id", "unknown")
    sender_info = parsed_data.get("from") or {}
    if isinstance(sender_info, dict):
        sender_email = sender_info.get("email", "")
        sender_name = sender_info.get("name", "")
    else:
        sender_email = str(sender_info)
        sender_name = ""

    from_domain = _extract_domain(sender_email)
    date_str = parsed_data.get("date")

    # Combine Authentication-Results and ARC-Authentication-Results
    auth_headers = (
        _get_headers_list(raw_headers, "Authentication-Results")
        + _get_headers_list(raw_headers, "ARC-Authentication-Results")
    )
    all_auth_text = " ".join(auth_headers).lower()

    # --- SPF ---
    spf = "none"
    rec_spf = " ".join(_get_headers_list(raw_headers, "Received-SPF")).lower()
    if "pass" in rec_spf or "spf=pass" in all_auth_text:
        spf = "pass"
    elif "fail" in rec_spf or "spf=fail" in all_auth_text:
        spf = "fail"
    elif "softfail" in rec_spf or "spf=softfail" in all_auth_text:
        spf = "softfail"
    elif "neutral" in rec_spf or "spf=neutral" in all_auth_text:
        spf = "neutral"
    elif "permerror" in rec_spf or "spf=permerror" in all_auth_text:
        spf = "permerror"
    elif "temperror" in rec_spf or "spf=temperror" in all_auth_text:
        spf = "temperror"

    # --- DKIM ---
    dkim = "none"
    if "dkim=pass" in all_auth_text:
        dkim = "pass"
    elif "dkim=fail" in all_auth_text:
        dkim = "fail"
    elif "dkim=permerror" in all_auth_text or "dkim=temperror" in all_auth_text:
        dkim = "permerror"
    elif _get_headers_list(raw_headers, "DKIM-Signature"):
        # Has DKIM signature but no auth results header
        dkim = "pass"

    # --- DMARC ---
    dmarc = "none"
    dmarc_policy = "none"
    if "dmarc=pass" in all_auth_text:
        dmarc = "pass"
    elif "dmarc=fail" in all_auth_text:
        dmarc = "fail"

    # DMARC policy detection
    pol_match = re.search(r"\bp=([a-z]+)\b", all_auth_text)
    if pol_match:
        dmarc_policy = pol_match.group(1).lower()

    # --- Domain Alignment ---
    spf_aligned = True
    dkim_aligned = True

    # Check Return-Path / smtp.mailfrom for SPF alignment
    return_path_list = _get_headers_list(raw_headers, "Return-Path")
    if return_path_list and from_domain:
        rp_domain = _extract_domain(return_path_list[0])
        if rp_domain and not (rp_domain == from_domain or rp_domain.endswith("." + from_domain) or from_domain.endswith("." + rp_domain)):
            spf_aligned = False

    # Check DKIM d= or header.i= domain alignment
    dkim_signatures = _get_headers_list(raw_headers, "DKIM-Signature")
    if dkim_signatures and from_domain:
        d_match = re.search(r"\bd=([a-zA-Z0-9\.\-_]+)", dkim_signatures[0])
        if d_match:
            dkim_domain = d_match.group(1).lower()
            if not (dkim_domain == from_domain or dkim_domain.endswith("." + from_domain) or from_domain.endswith("." + dkim_domain)):
                dkim_aligned = False

    # If SPF or DKIM failed, alignment is false
    if spf == "fail":
        spf_aligned = False
    if dkim == "fail":
        dkim_aligned = False

    # --- Red Flags ---
    red_flags = []

    # 1. Reply-To mismatch
    reply_to = parsed_data.get("reply_to")
    if reply_to and from_domain:
        rt_domain = _extract_domain(reply_to)
        if rt_domain and rt_domain != from_domain:
            red_flags.append("reply-to mismatch")

    # 2. Display Name Spoofing
    if sender_name and "@" in sender_name:
        fake_email_domain = _extract_domain(sender_name)
        if fake_email_domain and fake_email_domain != from_domain:
            red_flags.append("display-name spoofing")

    # 3. Known executive / VIP display name spoofing
    vip_keywords = ["ceo", "cfo", "paypal", "microsoft", "apple", "google security", "it helpdesk", "bank"]
    lower_name = sender_name.lower()
    if any(vip in lower_name for vip in vip_keywords):
        if not any(vip in from_domain for vip in ["google.com", "microsoft.com", "apple.com", "paypal.com"]):
            red_flags.append(f"display-name spoofing: {sender_name}")

    originating_ip = extract_originating_ip(raw_headers, received_chain)

    return {
        "message_id": message_id,
        "sender_email": sender_email,
        "originating_ip": originating_ip,
        "date": date_str,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "dmarc_policy": dmarc_policy,
        "alignment": {
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
        },
        "red_flags": red_flags,
    }


def main():
    parser = argparse.ArgumentParser(description="Email header forensics analyzer.")
    parser.add_argument("--input-dir", help="Directory of parsed email JSON files.")
    parser.add_argument("--input-file", help="Single parsed email JSON file.")
    parser.add_argument("--output-dir", default="./data/forensics", help="Directory to save forensics JSON files.")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    if args.input_file:
        files = [args.input_file]
    elif args.input_dir:
        files = sorted(glob.glob(os.path.join(args.input_dir, "*.json")))
    else:
        print("Please provide --input-dir or --input-file")
        sys.exit(1)

    for filepath in files:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        forensics = analyze_forensics(data)
        out_name = os.path.basename(filepath)
        out_path = os.path.join(args.output_dir, out_name)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(forensics, f, indent=2)

        print(f"Forensics analyzed: {out_name} (SPF: {forensics['spf']}, DKIM: {forensics['dkim']}, IP: {forensics['originating_ip']})")


if __name__ == "__main__":
    main()
