import os
import base64
from typing import Generator
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class GmailClient:
    def __init__(self):
        self.creds_file = os.environ.get("GMAIL_CREDENTIALS_FILE", "credentials.json")
        self.token_file = os.environ.get("GMAIL_TOKEN_FILE", "token.json")
        self.creds = None
        
        if os.path.exists(self.token_file):
            self.creds = Credentials.from_authorized_user_file(self.token_file, SCOPES)
            
        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
            else:
                if not os.path.exists(self.creds_file):
                    raise ValueError(f"Gmail credentials file {self.creds_file} not found. Ensure it exists or set GMAIL_CREDENTIALS_FILE.")
                flow = InstalledAppFlow.from_client_secrets_file(self.creds_file, SCOPES)
                self.creds = flow.run_local_server(port=0)
            with open(self.token_file, 'w') as token:
                token.write(self.creds.to_json())
                
        self.service = build('gmail', 'v1', credentials=self.creds)

    def fetch_emails(self, limit: int = 10, since_date: str = None) -> Generator[bytes, None, None]:
        query = ""
        if since_date:
            query = f"after:{since_date}"
            
        results = self.service.users().messages().list(userId='me', q=query, maxResults=limit).execute()
        messages = results.get('messages', [])
        
        for msg in messages:
            msg_id = msg['id']
            message_data = self.service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
            raw_email = base64.urlsafe_b64decode(message_data['raw'])
            yield raw_email
