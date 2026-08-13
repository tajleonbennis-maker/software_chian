"""Collect and normalize public product-trend signals used by the research brain."""
import hashlib
import re
import time
from typing import Any, Dict, List

import requests


class TrendIntelligenceError(RuntimeError):
    pass


class FofaHotSearchSource:
    """Adapter for the public hot-search feed used by FOFA's official homepage."""

    URL = "https://api.fofa.info/v1/hotsearch"

    def __init__(self, timeout: int = 20):
        self.timeout = timeout

    def fetch(self) -> List[Dict[str, Any]]:
        response = requests.get(
            self.URL,
            params={"ts": int(time.time() * 1000)},
            headers={"User-Agent": "SupplyChainResearchBrain/1.0", "Accept": "application/json"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("code") != 0 or not isinstance(payload.get("data"), list):
            raise TrendIntelligenceError(payload.get("message") or "热搜响应结构异常")
        return [self._normalize(item, rank) for rank, item in enumerate(payload["data"], 1)]

    @staticmethod
    def _normalize(item: Dict[str, Any], rank: int) -> Dict[str, Any]:
        name = str(item.get("app") or "").strip()
        query = str(item.get("query_string") or "").strip()
        trend = item.get("hot_trend") if isinstance(item.get("hot_trend"), list) else []
        values = [max(0, int(point.get("value") or 0)) for point in trend if isinstance(point, dict)]
        recent = values[-3:]
        previous = values[-6:-3]
        recent_avg = sum(recent) / len(recent) if recent else 0
        previous_avg = sum(previous) / len(previous) if previous else 0
        momentum = recent_avg - previous_avg
        hot_score = round(recent_avg + max(-250, min(500, momentum)) + (300 if item.get("is_hot") else 0), 2)
        return {
            "signal_key": hashlib.sha256(f"fofa-hot:{name}:{query}".encode()).hexdigest(),
            "source": "fofa_hot_search",
            "name": name,
            "query": query,
            "rank": rank,
            "is_hot": bool(item.get("is_hot")),
            "asset_count": int(item.get("asset_count") or 0),
            "hot_score": hot_score,
            "momentum": round(momentum, 2),
            "trend": trend,
            "raw": item,
        }


def slugify_trend(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:64]
    return f"trend-{slug or hashlib.sha1(name.encode()).hexdigest()[:12]}"
