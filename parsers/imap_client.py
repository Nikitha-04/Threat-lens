import imaplib
import logging
import os
import time
from typing import Generator, List, Tuple

from parsers.email_parser import extract_safe_message_id

logger = logging.getLogger(__name__)


def quote_folder_name(folder: str) -> str:
    """
    Ensure IMAP folder names with spaces or brackets are appropriately quoted.
    e.g. [Gmail]/All Mail -> '"[Gmail]/All Mail"'
    """
    cleaned = folder.strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        return cleaned
    if " " in cleaned or "/" in cleaned or "[" in cleaned or "]" in cleaned:
        return f'"{cleaned}"'
    return cleaned


class IMAPClient:
    FOLDER_MAP = {
        "inbox": "INBOX",
        "spam": '"[Gmail]/Spam"',
        "junk": '"[Gmail]/Spam"',
        "all": '"[Gmail]/All Mail"',
        "all mail": '"[Gmail]/All Mail"',
        "all_mail": '"[Gmail]/All Mail"',
    }

    def __init__(self):
        self.host = os.environ.get("IMAP_HOST")
        self.user = os.environ.get("IMAP_USER")
        self.password = os.environ.get("IMAP_PASSWORD")

        if not all([self.host, self.user, self.password]):
            raise ValueError("IMAP_HOST, IMAP_USER, and IMAP_PASSWORD must be set for IMAP ingestion.")

    def _login(self) -> imaplib.IMAP4_SSL:
        mail = imaplib.IMAP4_SSL(self.host)
        mail.login(self.user, self.password)
        return mail

    def log_folder_status(self) -> dict[str, int]:
        """
        Log the IMAP_USER account and message counts for INBOX, [Gmail]/Spam, and [Gmail]/All Mail.
        Returns a dict of folder name -> message count.
        """
        mail = self._login()
        logger.info("IMAP Account: %s (Host: %s)", self.user, self.host)

        target_folders = [
            ("INBOX", "INBOX"),
            ("[Gmail]/Spam", '"[Gmail]/Spam"'),
            ("[Gmail]/All Mail", '"[Gmail]/All Mail"'),
        ]

        counts = {}
        for display_name, quoted_name in target_folders:
            try:
                status, data = mail.select(quoted_name, readonly=True)
                if status == "OK" and data and data[0]:
                    count = int(data[0].decode())
                else:
                    count = 0
                counts[display_name] = count
                logger.info("Folder %-20s message count: %d", f"'{display_name}'", count)
            except Exception as exc:
                logger.warning("Could not select folder '%s': %s", display_name, exc)
                counts[display_name] = 0

        try:
            mail.logout()
        except Exception:
            pass

        return counts

    def normalize_folders(self, folder_arg: str | List[str]) -> List[str]:
        """
        Convert user-supplied folder list or comma-separated string to quoted IMAP folder names.
        """
        if isinstance(folder_arg, str):
            parts = [p.strip() for p in folder_arg.split(",") if p.strip()]
        else:
            parts = [p.strip() for p in folder_arg if p.strip()]

        normalized = []
        for p in parts:
            p_lower = p.lower()
            if p_lower in self.FOLDER_MAP:
                normalized.append(self.FOLDER_MAP[p_lower])
            else:
                normalized.append(quote_folder_name(p))
        return normalized

    def download_emails(
        self,
        raw_dir: str = "./data/raw",
        limit: int = 50,
        since_date: str | None = None,
        folders: str | List[str] = "inbox,spam",
    ) -> Tuple[List[dict], dict[str, dict]]:
        """
        Download all raw emails for the selected folders in one pass.
        Reconnects and retries up to 3 times if connection drops mid-way.
        Saves each message to ./data/raw/{message_id}.eml.
        Logs 'downloaded X of Y messages in <folder>' per folder.
        Closes the IMAP connection before returning.
        Returns (downloaded_items, folder_status).
        """
        os.makedirs(raw_dir, exist_ok=True)
        mail = self._login()
        norm_folders = self.normalize_folders(folders)

        downloaded_items = []
        folder_status = {}

        for folder in norm_folders:
            folder_clean = folder.strip('"\'')
            downloaded_in_folder = 0
            expected_in_folder = 0
            folder_error = None

            # 1. Select folder with up to 3 retries
            selected = False
            for attempt in range(3):
                try:
                    status, select_data = mail.select(folder, readonly=True)
                    if status == "OK":
                        selected = True
                        break
                    else:
                        folder_error = f"Select returned status: {status}"
                except Exception as exc:
                    folder_error = str(exc)
                    logger.warning("Connection dropped selecting folder %s (attempt %d/3): %s. Reconnecting...", folder_clean, attempt + 1, exc)
                    try:
                        mail.logout()
                    except Exception:
                        pass
                    time.sleep(1.0)
                    try:
                        mail = self._login()
                    except Exception as reconn_exc:
                        logger.warning("Reconnection failed: %s", reconn_exc)

            if not selected:
                logger.error("Failed to select folder %s: %s", folder_clean, folder_error)
                folder_status[folder_clean] = {
                    "fully_read": False,
                    "read": 0,
                    "expected": 0,
                    "error": folder_error,
                }
                continue

            # 2. Search message numbers
            try:
                search_criteria = "ALL"
                if since_date:
                    search_criteria = f'(SINCE "{since_date}")'

                status, messages = mail.search(None, search_criteria)
                if status != "OK" or not messages or not messages[0]:
                    msg_nums = []
                else:
                    msg_nums = messages[0].split()[::-1]  # Most recent first
            except Exception as search_exc:
                logger.error("Failed to search folder %s: %s", folder_clean, search_exc)
                folder_status[folder_clean] = {
                    "fully_read": False,
                    "read": 0,
                    "expected": 0,
                    "error": str(search_exc),
                }
                continue

            if limit and limit > 0:
                msg_nums = msg_nums[:limit]
            expected_in_folder = len(msg_nums)

            # 3. Fetch each raw message with retry
            for num in msg_nums:
                raw_bytes = None
                fetch_err = None
                for attempt in range(3):
                    try:
                        status, data = mail.fetch(num, "(RFC822)")
                        if status == "OK" and data and data[0] and isinstance(data[0], tuple):
                            raw_bytes = data[0][1]
                            break
                        else:
                            fetch_err = f"Fetch status {status}"
                    except Exception as exc:
                        fetch_err = str(exc)
                        logger.warning("Connection dropped fetching message %s in %s (attempt %d/3): %s. Reconnecting...", num.decode(errors="ignore") if isinstance(num, bytes) else str(num), folder_clean, attempt + 1, exc)
                        try:
                            mail.logout()
                        except Exception:
                            pass
                        time.sleep(1.0)
                        try:
                            mail = self._login()
                            mail.select(folder, readonly=True)
                        except Exception as reconn_exc:
                            logger.warning("Reconnection failed: %s", reconn_exc)

                if raw_bytes is None:
                    folder_error = f"Message fetch failed: {fetch_err}"
                    logger.error("Failed to fetch message in %s after 3 attempts: %s", folder_clean, fetch_err)
                    continue

                safe_id = extract_safe_message_id(raw_bytes)
                eml_path = os.path.join(raw_dir, f"{safe_id}.eml")
                try:
                    with open(eml_path, "wb") as f:
                        f.write(raw_bytes)
                except Exception as write_exc:
                    logger.error("Failed writing EML %s: %s", eml_path, write_exc)

                downloaded_in_folder += 1
                downloaded_items.append({
                    "message_id": safe_id,
                    "folder": folder_clean,
                    "eml_path": eml_path,
                    "raw_bytes": raw_bytes,
                })

            logger.info(
                "downloaded %d of %d messages in %s",
                downloaded_in_folder,
                expected_in_folder,
                folder_clean,
            )

            fully_read = (downloaded_in_folder == expected_in_folder)
            folder_status[folder_clean] = {
                "fully_read": fully_read,
                "read": downloaded_in_folder,
                "expected": expected_in_folder,
                "error": folder_error if not fully_read else None,
            }

        # 4. Close IMAP connection
        try:
            mail.logout()
        except Exception:
            pass

        return downloaded_items, folder_status

    def fetch_emails(
        self,
        limit: int = 50,
        since_date: str = None,
        folders: str | List[str] = "inbox,spam",
    ) -> Generator[bytes, None, None]:
        """
        Download-first generator yielding raw email bytes.
        """
        downloaded, _ = self.download_emails(
            raw_dir="./data/raw",
            limit=limit,
            since_date=since_date,
            folders=folders,
        )
        for item in downloaded:
            yield item["raw_bytes"]
