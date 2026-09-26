"""Copy a Kafka JSON body onto the event.

ansible.eda 2.12 stores the message under ``body``. The rules match ``event.kind``.
"""

from typing import Dict


def main(event: Dict[str, object]) -> Dict[str, object]:
    """Return the Kafka payload with the source metadata kept under ``meta``."""
    body = event.get("body")
    if not isinstance(body, dict):
        message = "Kafka event body is not a JSON object"
        raise ValueError(message)
    hoisted: Dict[str, object] = dict(body)
    meta = event.get("meta")
    if isinstance(meta, dict):
        hoisted["meta"] = meta
    return hoisted
