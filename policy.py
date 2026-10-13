"""Policy engine: category blocklists per client group, rate limiting,
and a simple heuristic for auto-generated (DGA-like) domains."""
import ipaddress
import json
import math
import time
from collections import Counter, defaultdict, deque


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


class Policy:
    def __init__(self, rules):
        """rules: path to a JSON file, or an already-loaded dict."""
        if isinstance(rules, str):
            with open(rules) as f:
                rules = json.load(f)
        self.rules = rules
        self.domain_category = {}
        for category, domains in rules.get("categories", {}).items():
            for d in domains:
                self.domain_category[d.lower()] = category
        rl = rules.get("rate_limit", {})
        self.max_requests = rl.get("max_requests", 100)
        self.window = rl.get("window_seconds", 10)
        self._hits = defaultdict(deque)

    # ---- helpers -------------------------------------------------------
    def category_of(self, host: str):
        """Match host or any parent domain (a.b.facebook.com -> facebook.com)."""
        parts = host.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.domain_category:
                return self.domain_category[candidate]
        return None

    def rate_limited(self, client_ip: str) -> bool:
        now = time.monotonic()
        q = self._hits[client_ip]
        while q and now - q[0] > self.window:
            q.popleft()
        q.append(now)
        return len(q) > self.max_requests

    @staticmethod
    def looks_generated(host: str) -> bool:
        """Flag long, high-entropy second-level labels that are digit-heavy or
        vowel-poor (typical of domain generation algorithms). Heuristic only:
        it can produce false positives."""
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            pass
        parts = host.split(".")
        if len(parts) < 2:
            return False
        label = parts[-2]
        if len(label) < 12:
            return False
        digits = sum(ch.isdigit() for ch in label) / len(label)
        vowels = sum(ch in "aeiou" for ch in label) / len(label)
        return shannon_entropy(label) >= 3.2 and (digits >= 0.2 or vowels < 0.25)

    # ---- main entry ----------------------------------------------------
    def decide(self, host: str, client_ip: str):
        """Return (action, category, reason)."""
        if self.rate_limited(client_ip):
            return "block", "rate_limit", "too many requests from client"
        group = self.rules.get("client_groups", {}).get(client_ip, "default")
        blocked = set(self.rules.get("groups", {}).get(group, {}).get("block_categories", []))
        category = self.category_of(host)
        if category and category in blocked:
            return "block", category, f"category '{category}' blocked for group '{group}'"
        if self.looks_generated(host):
            return "block", "suspicious", "domain looks auto-generated"
        return "allow", category or "uncategorized", "allowed"
