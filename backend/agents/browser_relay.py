"""
SentinelAI - Browser Relay
Bridges the Chrome extension to the backend multi-model engine.
"""
import asyncio
import requests
import json
from datetime import datetime

class BrowserRelay:
    def __init__(self, backend_url="http://localhost:8000"):
        self.backend_url = backend_url
        self.agent_name = "browser_extension"

    async def start(self):
        print(f"[*] Starting {self.agent_name} relay...")
        while True:
            try:
                # Heartbeat
                requests.post(f"{self.backend_url}/agents/heartbeat/{self.agent_name}")
            except:
                pass
            await asyncio.sleep(30)

    def relay_url(self, url: str):
        payload = {"url": url, "source": self.agent_name}
        try:
            return requests.post(f"{self.backend_url}/analyse", json=payload).json()
        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    relay = BrowserRelay()
    asyncio.run(relay.start())
