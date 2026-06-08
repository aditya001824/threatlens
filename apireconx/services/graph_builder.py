from __future__ import annotations

from collections import defaultdict

from apireconx.schemas import AttackGraph, GraphEdge, GraphNode
from apireconx.storage import AppStore, store


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_attack_graph(app_store: AppStore = store) -> AttackGraph:
    endpoints = app_store.list_endpoints()
    latest_scans = app_store.list_scans(limit=1)
    findings = app_store.list_findings(scan_id=latest_scans[0].scan_id, limit=500) if latest_scans else []

    finding_by_endpoint = defaultdict(list)
    for finding in findings:
        if finding.endpoint_id:
            finding_by_endpoint[finding.endpoint_id].append(finding)

    nodes: list[GraphNode] = [
        GraphNode(id="entry", label="API Entry", kind="entry", severity="info"),
    ]
    edges: list[GraphEdge] = []

    role_nodes = set()
    for endpoint in endpoints:
        severity = _max_severity(finding_by_endpoint[endpoint.id])
        nodes.append(
            GraphNode(
                id=endpoint.id,
                label=f"{endpoint.method} {endpoint.path}",
                kind="endpoint",
                severity=severity,
                metadata={"summary": endpoint.summary, "auth_required": endpoint.auth_required, "source": endpoint.source},
            )
        )

        role = "authenticated" if endpoint.auth_required else "public"
        role_id = f"role:{role}"
        if role_id not in role_nodes:
            role_nodes.add(role_id)
            nodes.append(GraphNode(id=role_id, label=role.title(), kind="role", severity="info"))

        edges.append(
            GraphEdge(
                id=f"edge:{role_id}:{endpoint.id}",
                source=role_id if endpoint.auth_required else "entry",
                target=endpoint.id,
                label="can reach",
                risk=severity,
            )
        )

    for finding in findings:
        if not finding.endpoint_id:
            continue
        node_id = f"finding:{finding.id}"
        nodes.append(
            GraphNode(
                id=node_id,
                label=finding.title,
                kind="finding",
                severity=finding.severity,
                metadata={"category": finding.category, "scan_id": finding.scan_id},
            )
        )
        edges.append(
            GraphEdge(
                id=f"edge:{finding.endpoint_id}:{node_id}",
                source=finding.endpoint_id,
                target=node_id,
                label=finding.category,
                risk=finding.severity,
            )
        )

    _add_inferred_escalation_edges(edges, endpoints, finding_by_endpoint)
    return AttackGraph(nodes=nodes, edges=edges)


def _max_severity(findings: list) -> str:
    if not findings:
        return "info"
    return max((finding.severity for finding in findings), key=lambda sev: SEVERITY_ORDER.get(sev, 0))


def _add_inferred_escalation_edges(edges: list[GraphEdge], endpoints: list, finding_by_endpoint: dict) -> None:
    risky = [endpoint for endpoint in endpoints if any(f.category in {"bola", "broken_authentication", "mass_assignment"} for f in finding_by_endpoint[endpoint.id])]
    admin = [endpoint for endpoint in endpoints if "admin" in endpoint.path.lower() or "admin" in " ".join(endpoint.tags).lower()]
    for source in risky:
        for target in admin:
            if source.id == target.id:
                continue
            edges.append(
                GraphEdge(
                    id=f"edge:escalate:{source.id}:{target.id}",
                    source=source.id,
                    target=target.id,
                    label="possible escalation path",
                    risk="high",
                    metadata={"inferred": True},
                )
            )
