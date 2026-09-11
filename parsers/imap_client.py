import imaplib
import os
from typing import Generator

class IMAPClient:
    def __init__(self):
        self.host = os.environ.get("IMAP_HOST")
        self.user = os.environ.get("IMAP_USER")
        self.password = os.environ.get("IMAP_PASSWORD")
        
        if not all([self.host, self.user, self.password]):
            raise ValueError("IMAP_HOST, IMAP_USER, and IMAP_PASSWORD must be set for IMAP ingestion.")
            
    def fetch_emails(self, limit: int = 10, since_date: str = None) -> Generator[bytes, None, None]:
        mail = imaplib.IMAP4_SSL(self.host)
        mail.login(self.user, self.password)
        mail.select("inbox")
        
        search_criteria = "ALL"
        if since_date:
            search_criteria = f'(SINCE "{since_date}")'
            
        status, messages = mail.search(None, search_criteria)
        if status != "OK":
            raise Exception(f"Failed to search emails: {status}")
            
        msg_nums = messages[0].split()
        msg_nums = msg_nums[::-1]
        
        if limit:
            msg_nums = msg_nums[:limit]
            
        for num in msg_nums:
            status, data = mail.fetch(num, "(RFC822)")
            if status == "OK" and data and data[0]:
                raw_email = data[0][1]
                yield raw_email
                
        mail.close()
        mail.logout()
