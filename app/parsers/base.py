import time
from abc import ABC, abstractmethod


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
            self.entries = [e for e in self.entries if e.get("ip") not in skip]
            parsed = len(self.entries)

        self.processing_ms = round((time.time() - t0) * 1000, 1)
        self._compute_time_range()
        return self._build_report(total, parsed)

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
