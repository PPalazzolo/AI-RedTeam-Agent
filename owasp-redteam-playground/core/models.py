"""Selectable OpenAI models exposed to the UI dropdown.

To add a model: append a dict here. Nothing else changes.
"""

MODELS = [
    {
        "id": "gpt-4o",
        "label": "GPT-4o",
        "description": "Most capable. Best refusal behaviour. Default.",
        "tier": "premium",
    },
    {
        "id": "gpt-4o-mini",
        "label": "GPT-4o mini",
        "description": "Cheaper and faster than GPT-4o, still strong refusals.",
        "tier": "balanced",
    },
    {
        "id": "gpt-4-turbo",
        "label": "GPT-4 Turbo",
        "description": "Previous generation flagship.",
        "tier": "premium",
    },
    {
        "id": "gpt-3.5-turbo",
        "label": "GPT-3.5 Turbo",
        "description": "Cheapest. Weaker safety \u2014 useful to see what failures look like.",
        "tier": "budget",
    },
]


def get_all() -> list[dict]:
    return list(MODELS)


def is_known(model_id: str) -> bool:
    return any(m["id"] == model_id for m in MODELS)
