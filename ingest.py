import argparse
import json
import os
import sys
import traceback
from dotenv import load_dotenv

from parsers.email_parser import parse_email

def main():
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Ingest and parse emails for threat detection.")
    parser.add_argument("--source", choices=["gmail", "imap", "file"], required=True, help="Email source")
    parser.add_argument("--limit", type=int, default=10, help="Max emails to fetch")
    parser.add_argument("--since", type=str, help="Fetch emails since date (e.g. 01-Jan-2023 for IMAP, 2023/01/01 for Gmail)")
    parser.add_argument("--file", type=str, help="File path if source is 'file'")
    
    args = parser.parse_args()
    
    parsed_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "parsed"))
    attach_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "attachments"))
    os.makedirs(parsed_dir, exist_ok=True)
    os.makedirs(attach_dir, exist_ok=True)
    
    email_generator = []
    
    if args.source == "gmail":
        from parsers.gmail_client import GmailClient
        try:
            client = GmailClient()
            email_generator = client.fetch_emails(limit=args.limit, since_date=args.since)
        except Exception as e:
            print(f"Failed to initialize Gmail client: {e}")
            sys.exit(1)
    elif args.source == "imap":
        from parsers.imap_client import IMAPClient
        try:
            client = IMAPClient()
            email_generator = client.fetch_emails(limit=args.limit, since_date=args.since)
        except Exception as e:
            print(f"Failed to initialize IMAP client: {e}")
            sys.exit(1)
    elif args.source == "file":
        if not args.file:
            print("Error: --file argument is required when source is file")
            sys.exit(1)
        def file_gen():
            with open(args.file, 'rb') as f:
                yield f.read()
        email_generator = file_gen()
        
    fetched = 0
    failed = 0
    with_attachments = 0
    
    for raw_bytes in email_generator:
        fetched += 1
        try:
            parsed_data = parse_email(raw_bytes, attachments_dir=attach_dir)
            if parsed_data.get("attachments"):
                with_attachments += 1
                
            # Fallback for save name
            import hashlib
            from parsers.email_parser import sanitize_filename
            safe_id = sanitize_filename(parsed_data.get("message_id"))
            if not safe_id or safe_id == "unnamed":
                safe_id = hashlib.sha256(raw_bytes).hexdigest()
                
            out_path = os.path.join(parsed_dir, f"{safe_id}.json")
            
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(parsed_data, f, indent=2, ensure_ascii=False)
                
            print(f"Processed: {safe_id}")
        except Exception as e:
            failed += 1
            import hashlib
            h = hashlib.sha256(raw_bytes).hexdigest()
            print(f"Failed to parse email {h}: {e}", file=sys.stderr)
            traceback.print_exc()
            
    print("\n--- Summary ---")
    print(f"Total Fetched: {fetched}")
    print(f"Failed: {failed}")
    print(f"With Attachments: {with_attachments}")

if __name__ == "__main__":
    main()
