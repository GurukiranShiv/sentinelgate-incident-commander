from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

try:
    from opensearchpy import OpenSearch
except Exception:  # pragma: no cover - optional dependency
    OpenSearch = None  # type: ignore

INDEX_PATH = Path(os.getenv("LOCAL_SEARCH_INDEX", "data/local_incident_index.jsonl"))


class SearchIndexService:
    """Indexes incident reports for SOC-style historical case search.

    Uses a local JSONL index by default. If ENABLE_OPENSEARCH=true, it also tries
    to index into OpenSearch. This keeps the project runnable locally and still
    supports a realistic SOC architecture in Docker mode.
    """

    def __init__(self) -> None:
        self.enabled = os.getenv("ENABLE_OPENSEARCH", "false").lower() == "true"
        self.index_name = os.getenv("OPENSEARCH_INDEX", "incident-commander-cases")
        self.client = None
        if self.enabled and OpenSearch:
            try:
                self.client = OpenSearch(
                    hosts=[{"host": os.getenv("OPENSEARCH_HOST", "localhost"), "port": int(os.getenv("OPENSEARCH_PORT", "9200"))}],
                    http_auth=(os.getenv("OPENSEARCH_USER", "admin"), os.getenv("OPENSEARCH_PASSWORD", "admin")),
                    use_ssl=os.getenv("OPENSEARCH_SSL", "false").lower() == "true",
                    verify_certs=False,
                )
                if not self.client.indices.exists(self.index_name):
                    self.client.indices.create(self.index_name)
            except Exception:
                self.client = None
                self.enabled = False

    def index_case(self, case_id: int | None, result: Dict[str, Any]) -> None:
        INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "case_id": case_id,
            "generated_at": result.get("generated_at"),
            "incident_type": result.get("incident_type"),
            "incident_type_id": result.get("incident_type_id"),
            "severity": result.get("severity"),
            "environment": result.get("environment"),
            "summary": result.get("case_summary", {}).get("commander_brief", ""),
            "indicators": result.get("indicators", []),
            "assets": result.get("affected_assets", []),
            "mitre_tactics": result.get("mitre_tactics", []),
        }
        with INDEX_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(doc) + "\n")
        if self.client:
            try:
                self.client.index(index=self.index_name, id=str(case_id or result.get("generated_at")), body=doc)
            except Exception:
                return

    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        limit = max(1, min(limit, 50))
        if self.client:
            try:
                response = self.client.search(
                    index=self.index_name,
                    body={
                        "size": limit,
                        "query": {
                            "multi_match": {
                                "query": query,
                                "fields": ["incident_type^3", "summary", "indicators", "assets", "mitre_tactics"],
                            }
                        },
                    },
                )
                return [hit["_source"] for hit in response.get("hits", {}).get("hits", [])]
            except Exception:
                pass

        if not INDEX_PATH.exists():
            return []
        needle = query.lower().strip()
        matches: List[Dict[str, Any]] = []
        with INDEX_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                haystack = json.dumps(doc).lower()
                if not needle or needle in haystack:
                    matches.append(doc)
        return list(reversed(matches))[:limit]
