from fastapi import APIRouter, HTTPException

from apireconx.schemas import AttackRecord, ReplayRequest
from apireconx.services.scanner import scanner
from apireconx.storage import store


router = APIRouter(prefix="/api/attacks", tags=["attacks"])


@router.get("", response_model=list[AttackRecord])
def list_attacks(scan_id: str | None = None) -> list[AttackRecord]:
    return store.list_attacks(scan_id=scan_id)


@router.post("/{attack_id}/replay", response_model=AttackRecord)
async def replay_attack(attack_id: str, payload: ReplayRequest) -> AttackRecord:
    if not payload.authorized:
        raise HTTPException(status_code=403, detail="Replay requires authorized=true for owned or approved targets.")
    attack = store.get_attack(attack_id)
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    if not attack.replayable:
        raise HTTPException(status_code=400, detail="Attack is not replayable")
    return await scanner.replay_attack(attack, timeout_seconds=payload.timeout_seconds, override_base_url=payload.override_base_url)
