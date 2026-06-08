from apireconx.schemas import ApiEndpoint
from apireconx.services.attack_generator import generate_attack_cases


def test_attack_generator_creates_business_logic_and_bola_cases() -> None:
    endpoint = ApiEndpoint(
        id="post-transfer",
        method="POST",
        path="/transfer",
        parameters=[],
        request_schema={
            "type": "object",
            "properties": {
                "sender": {"type": "string"},
                "receiver": {"type": "string"},
                "amount": {"type": "integer"},
            },
        },
        auth_required=True,
    )

    cases = generate_attack_cases(endpoint)
    names = {case.name for case in cases}

    assert "BOLA object swap" in names
    assert "Negative numeric value" in names
    assert "Integer boundary value" in names
