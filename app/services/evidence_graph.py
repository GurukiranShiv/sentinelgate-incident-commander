from __future__ import annotations

import os
import re
from typing import Any, Dict, List

try:
    from neo4j import GraphDatabase
except Exception:  # pragma: no cover - optional dependency
    GraphDatabase = None  # type: ignore


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.:-]", "_", value.strip())
    return cleaned[:96] or "unknown"


class EvidenceGraphService:
    """Stores and renders incident relationship graphs.

    The project works without Neo4j. When ENABLE_NEO4J=true and Neo4j credentials are
    available, the same graph is also persisted in Neo4j. This gives the project a
    real attack-graph architecture without making local demo setup painful.
    """

    def __init__(self) -> None:
        self.enabled = os.getenv("ENABLE_NEO4J", "false").lower() == "true"
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "incidentcommander")
        self._driver = None
        if self.enabled and GraphDatabase:
            try:
                self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            except Exception:
                self._driver = None
                self.enabled = False

    def build_graph(self, result: Dict[str, Any]) -> Dict[str, Any]:
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, str]] = []

        def node(node_id: str, label: str, kind: str) -> None:
            nodes[node_id] = {"id": node_id, "label": label, "type": kind}

        incident_id = f"incident:{_safe_id(result['incident_type_id'])}"
        node(incident_id, result["incident_type"], "incident")

        for tactic in result.get("mitre_tactics", []):
            tactic_id = f"tactic:{_safe_id(tactic)}"
            node(tactic_id, tactic, "mitre_tactic")
            edges.append({"source": incident_id, "target": tactic_id, "relationship": "MAPS_TO"})

        previous = incident_id
        for step in result.get("attack_storyline", []):
            step_id = f"story:{_safe_id(step)}"
            node(step_id, step, "attack_storyline")
            edges.append({"source": previous, "target": step_id, "relationship": "NEXT"})
            previous = step_id

        for asset in result.get("affected_assets", []):
            asset_id = f"asset:{_safe_id(asset)}"
            node(asset_id, asset, "asset")
            edges.append({"source": incident_id, "target": asset_id, "relationship": "AFFECTS"})

        for indicator in result.get("indicators", []):
            indicator_id = f"ioc:{_safe_id(indicator)}"
            node(indicator_id, indicator, "indicator")
            edges.append({"source": indicator_id, "target": incident_id, "relationship": "SUPPORTS"})

        for gate in result.get("evidence_gated_actions", []):
            action_id = f"action:{_safe_id(gate['action'])}"
            node(action_id, gate["action"], f"approval_{gate['approval_level'].lower()}")
            edges.append({"source": incident_id, "target": action_id, "relationship": "RECOMMENDS"})
            for evidence in gate.get("verified_evidence", []):
                evidence_id = f"evidence:{_safe_id(evidence)}"
                node(evidence_id, evidence, "verified_evidence")
                edges.append({"source": evidence_id, "target": action_id, "relationship": "VERIFIES"})
            for evidence in gate.get("missing_evidence", []):
                evidence_id = f"missing:{_safe_id(evidence)}"
                node(evidence_id, evidence, "missing_evidence")
                edges.append({"source": evidence_id, "target": action_id, "relationship": "REQUIRED_FOR"})

        return {"nodes": list(nodes.values()), "edges": edges}

    def persist(self, result: Dict[str, Any]) -> None:
        if not self._driver:
            return
        graph = self.build_graph(result)
        try:
            with self._driver.session() as session:
                for n in graph["nodes"]:
                    session.run(
                        "MERGE (n:SecurityNode {id: $id}) SET n.label=$label, n.type=$type",
                        id=n["id"], label=n["label"], type=n["type"],
                    )
                for e in graph["edges"]:
                    session.run(
                        """
                        MATCH (a:SecurityNode {id: $source})
                        MATCH (b:SecurityNode {id: $target})
                        MERGE (a)-[r:RELATES {relationship: $relationship}]->(b)
                        """,
                        source=e["source"], target=e["target"], relationship=e["relationship"],
                    )
        except Exception:
            # For portfolio/demo reliability, graph persistence should never break IR report generation.
            return
