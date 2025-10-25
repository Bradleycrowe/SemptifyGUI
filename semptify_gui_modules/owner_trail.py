"""Owner trail stub.

Tracks ownership changes and records chain-of-custody-like events.
"""

def record_owner_change(owner_id, change, context=None):
    """Return a small record representing the owner change.

    Args:
        owner_id: identifier
        change: description
        context: optional dict

    Returns:
        dict: record
    """
    import time
    return {"owner_id": owner_id, "change": change, "context": context or {}, "ts": int(time.time())}
