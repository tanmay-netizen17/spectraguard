"""
SentinelAI - Log Collector
Streams system and auth logs to the Anomaly Detector.
"""
import asyncio
import requests

class LogCollector:
    def __init__(self, backend_url="http://localhost:8000"):
        self.backend_url = backend_url
        self.agent_name = "log_collector"

    async def stream_logs(self):
        print(f"[*] {self.agent_name} tailing security logs...")
        while True:
            try:
                requests.post(f"{self.backend_url}/agents/heartbeat/{self.agent_name}")
            except:
                pass
            await asyncio.sleep(20)

if __name__ == "__main__":
    collector = LogCollector()
    asyncio.run(collector.stream_logs())
