from fastapi import APIRouter

from apireconx.schemas import AttackGraph
from apireconx.services.graph_builder import build_attack_graph


router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("", response_model=AttackGraph)
def attack_graph() -> AttackGraph:
    return build_attack_graph()
