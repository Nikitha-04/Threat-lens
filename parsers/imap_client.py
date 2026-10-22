import imaplib
import logging
import os
from typing import Generator, List, Tuple

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

    def fetch_emails(
        self,
        limit: int = 50,
        since_date: str = None,
        folders: str | List[str] = "inbox,spam",
    ) -> Generator[bytes, None, None]:
        """
        Fetch emails from specified folders in read-only mode.
        limit: 0 means no limit (all emails).
        Yields raw email bytes.
        """
        mail = self._login()
        norm_folders = self.normalize_folders(folders)

        for folder in norm_folders:
            try:
                status, select_data = mail.select(folder, readonly=True)
                if status != "OK":
                    logger.warning("Failed to select folder %s (status=%s)", folder, status)
                    continue

                total_in_folder = int(select_data[0].decode()) if select_data and select_data[0] else 0

                search_criteria = "ALL"
                if since_date:
                    search_criteria = f'(SINCE "{since_date}")'

                status, messages = mail.search(None, search_criteria)
                if status != "OK":
                    logger.warning("Failed to search folder %s: status=%s", folder, status)
                    continue

                msg_nums = messages[0].split()
                # Most recent first
                msg_nums = msg_nums[::-1]

                fetch_count = len(msg_nums)
                if limit and limit > 0:
                    msg_nums = msg_nums[:limit]
                    fetch_count = len(msg_nums)

                logger.info(
                    "fetched %d of %d messages in %s",
                    fetch_count,
                    total_in_folder,
                    folder,
                )

                for num in msg_nums:
                    status, data = mail.fetch(num, "(RFC822)")
                    if status == "OK" and data and data[0] and isinstance(data[0], tuple):
                        raw_email = data[0][1]
                        yield raw_email

            except Exception as exc:
                logger.error("Error processing folder %s: %s", folder, exc)
                continue

        try:
            mail.logout()
        except Exception:
            pass
