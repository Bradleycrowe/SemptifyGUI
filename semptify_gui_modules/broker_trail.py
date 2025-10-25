"""Broker trail stub.

Captures and summarizes actions from brokers for auditing.
"""

def record_broker_action(broker_id, action, meta=None):
    """Return an audit tuple representing the recorded action (placeholder).

    Args:
        broker_id: identifier for the broker
        action: string describing the action
        meta: optional dict

    Returns:
        dict: {broker_id, action, meta, ts}
    """
    import time
    return {"broker_id": broker_id, "action": action, "meta": meta or {}, "ts": int(time.time())}
