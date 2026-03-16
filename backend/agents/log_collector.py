"""
SentinelAI — Log Collector Agent
Tails auth.log / syslog / Windows Event Log and forwards anomalous patterns to the API.
"""

from __future__ import annotations

import asyncio
import os
import httpx
import re
from datetime import datetime, timezone


# Patterns that warrant immediate forwarding even before scoring
HIGH_SIGNAL_PATTERNS = [
    re.compile(r"(authentication failure|failed password|invalid user)", re.IGNORECASE),
    re.compile(r"(brute.?force|too many auth)", re.IGNORECASE),
    re.compile(r"(sudo:.+NOT in sudoers)", re.IGNORECASE),
    re.compile(r"(new session|session opened for user root)", re.IGNORECASE),
]


class LogCollector:
    """
    Tails system log files and batches suspicious lines to /ingest/log.
    Supports: /var/log/auth.log, /var/log/syslog, custom paths.
    """

    def __init__(self):
        self.log_paths = os.getenv(
            "LOG_PATHS",
            "/var/log/auth.log,/var/log/syslog"
        ).split(",")
        self.sentinel_api = os.getenv("SENTINEL_API_URL", "http://localhost:8000")
        self.batch_size = int(os.getenv("LOG_BATCH_SIZE", "50"))
        self.flush_interval = int(os.getenv("LOG_FLUSH_INTERVAL", "60"))

    async def run(self):
        """Tail all configured log files concurrently."""
        tasks = [self._tail_file(path) for path in self.log_paths if path.strip()]
        if tasks:
            await asyncio.gather(*tasks)
        else:
            print("[LogCollector] No log paths configured.")

    async def _tail_file(self, path: str):
        """Tail a single log file, batching and flushing suspicious lines."""
        path = path.strip()
        try:
            f = open(path, "r", errors="ignore")
            f.seek(0, 2)  # Seek to end
            print(f"[LogCollector] Tailing: {path}")
        except FileNotFoundError:
            print(f"[LogCollector] File not found: {path}. Skipping.")
            return

        buffer = []
        last_flush = asyncio.get_event_loop().time()

        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(1)
                # Periodic flush even if no high-signal content
                if asyncio.get_event_loop().time() - last_flush > self.flush_interval and buffer:
                    await self._flush(buffer, path)
                    buffer = []
                    last_flush = asyncio.get_event_loop().time()
                continue

            buffer.append(line.rstrip())

            # Immediate flush on high-signal patterns
            if any(p.search(line) for p in HIGH_SIGNAL_PATTERNS):
                await self._flush(buffer, path)
                buffer = []
                last_flush = asyncio.get_event_loop().time()
            elif len(buffer) >= self.batch_size:
                await self._flush(buffer, path)
                buffer = []
                last_flush = asyncio.get_event_loop().time()

    async def _flush(self, lines: list[str], source_path: str):
        payload = {
            "log_lines": "\n".join(lines),
            "log_type": "auth" if "auth" in source_path else "syslog",
        }
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{self.sentinel_api}/ingest/log", json=payload, timeout=30
                )
                result = resp.json()
                if result.get("sentinel_score", 0) > 30:
                    print(f"[LogCollector] Alert! Score: {result.get('sentinel_score')} "
                          f"({result.get('severity')}) from {source_path}")
            except Exception as e:
                print(f"[LogCollector] API error: {e}")


if __name__ == "__main__":
    collector = LogCollector()
    asyncio.run(collector.run())
