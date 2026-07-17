import time
from abc import ABC, abstractmethod

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class BaseParser(ABC):
    name: str = "base"
    description: str = ""

    def __init__(self):
        self.entries = []
        self.errors = 0
        self.start_time = None
        self.end_time = None
        self.processing_ms = 0

    def parse(self, raw: str, exclude_ips: list[str] | None = None) -> dict:
        t0 = time.time()
        lines = raw.strip().splitlines()
        total = len(lines)
        parsed = 0
        self.entries = []
        self.errors = 0

        for line in lines:
            line = line.strip()
            if not line:
                continue
            entry = self._parse_line(line)
            if entry:
                self.entries.append(entry)
                parsed += 1
            else:
                self.errors += 1

        if exclude_ips:
            skip = set(exclude_ips)
            self.entries = [e for e in self.entries if self._get_ip(e) not in skip]
            parsed = len(self.entries)

        self.processing_ms = round((time.time() - t0) * 1000, 1)
        self._compute_time_range()
        return self._build_report(total, parsed)

    def _get_ip(self, entry: dict) -> str | None:
        return entry.get("ip") or entry.get("source_ip") or entry.get("client")

    @abstractmethod
    def _parse_line(self, line: str) -> dict | None:
        pass

    @abstractmethod
    def _build_report(self, total: int, parsed: int) -> dict:
        pass

    def _compute_time_range(self):
        timestamps = []
        for e in self.entries:
            ts = e.get("timestamp")
            if ts:
                timestamps.append(ts)
        if timestamps:
            self.start_time = min(timestamps)
            self.end_time = max(timestamps)

    @staticmethod
    def _hour_key(ts: str) -> str:
        if not ts:
            return "unknown"
        if "T" in ts:
            date_part = ts.split("T")[0]
            time_part = ts.split("T")[1]
            hour = time_part[:2] if len(time_part) >= 2 else "00"
            return f"{date_part} {hour}:00"
        parts = ts.split()
        if len(parts) >= 3:
            return parts[2][:2] + ":00" if len(parts[2]) >= 2 else "unknown"
        if len(parts) >= 2:
            return parts[1][:2] + ":00" if len(parts[1]) >= 2 else "unknown"
        return "unknown"
