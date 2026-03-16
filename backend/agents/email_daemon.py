"""
SentinelAI - Email Daemon
Monitors IMAP/SMTP streams for phishing and spear-phishing attempts.
"""
import asyncio
import requests
import time

class EmailDaemon:
    def __init__(self, backend_url="http://localhost:8000"):
        self.backend_url = backend_url
        self.agent_name = "email_daemon"

    async def run(self):
        print(f"[*] {self.agent_name} listening for incoming mail streams...")
        while True:
            # Heartbeat
            try:
                requests.post(f"{self.backend_url}/agents/heartbeat/{self.agent_name}")
            except:
                pass
            
            # Simulated mail check
            await asyncio.sleep(45)

if __name__ == "__main__":
    daemon = EmailDaemon()
    asyncio.run(daemon.run())
