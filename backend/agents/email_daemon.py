"""
SentinelAI — Email Daemon (IMAP IDLE)
Monitors a mailbox using IMAP IDLE and forwards suspicious emails to the orchestrator.
"""

from __future__ import annotations

import asyncio
import os
import email
import json
import httpx
from datetime import datetime, timezone

try:
    from imapclient import IMAPClient
    IMAP_AVAILABLE = True
except ImportError:
    IMAP_AVAILABLE = False


class EmailDaemon:
    """
    Connects to Gmail/Outlook via IMAP IDLE.
    Forwards every new email to /ingest/email endpoint for analysis.
    """

    def __init__(self):
        self.host = os.getenv("EMAIL_IMAP_HOST", "imap.gmail.com")
        self.user = os.getenv("EMAIL_USER", "")
        self.password = os.getenv("EMAIL_APP_PASSWORD", "")
        self.sentinel_api = os.getenv("SENTINEL_API_URL", "http://localhost:8000")

    async def run(self):
        """Main loop — reconnects on failure."""
        if not IMAP_AVAILABLE:
            print("[EmailDaemon] imapclient not installed. Daemon disabled.")
            return
        if not self.user or not self.password:
            print("[EmailDaemon] Email credentials not configured. Daemon disabled.")
            return

        while True:
            try:
                await self._connect_and_idle()
            except Exception as e:
                print(f"[EmailDaemon] Error: {e}. Reconnecting in 30s...")
                await asyncio.sleep(30)

    async def _connect_and_idle(self):
        with IMAPClient(self.host, ssl=True) as client:
            client.login(self.user, self.password)
            client.select_folder("INBOX")
            print(f"[EmailDaemon] Connected as {self.user}. Monitoring INBOX...")

            while True:
                # IMAP IDLE — waits for server push
                client.idle()
                responses = client.idle_check(timeout=300)
                client.idle_done()

                if responses:
                    # Fetch unread messages
                    messages = client.search(["UNSEEN"])
                    for uid in messages:
                        raw = client.fetch([uid], ["RFC822"])
                        for _, data in raw.items():
                            msg = email.message_from_bytes(data[b"RFC822"])
                            await self._process_email(msg)

    async def _process_email(self, msg: email.message.Message):
        """Extract text from email and POST to /ingest/email."""
        subject = msg.get("subject", "")
        sender = msg.get("from", "")
        body = self._extract_body(msg)
        headers = {k.lower(): v for k, v in msg.items()}

        payload = {
            "subject": subject,
            "body": body,
            "sender": sender,
            "headers": dict(headers),
        }

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(f"{self.sentinel_api}/ingest/email", json=payload, timeout=30)
                result = resp.json()
                print(f"[EmailDaemon] Email from '{sender}' → score: {result.get('sentinel_score', '?')}")
            except Exception as e:
                print(f"[EmailDaemon] Failed to ingest email: {e}")

    @staticmethod
    def _extract_body(msg: email.message.Message) -> str:
        """Extract text/plain body from email."""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    return part.get_payload(decode=True).decode("utf-8", errors="ignore")
        return msg.get_payload(decode=True).decode("utf-8", errors="ignore") if msg.get_payload() else ""


if __name__ == "__main__":
    daemon = EmailDaemon()
    asyncio.run(daemon.run())
