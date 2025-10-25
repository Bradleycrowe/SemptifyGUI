"""Greed watch dashboard stub.

Tracks and reports high-level 'greed' indicators across datasets.
"""

def watch_greed(events, threshold=5):
    """Return events that exceed a simple threshold (placeholder logic).

    Args:
        events: iterable of event dicts with numeric 'score' field
        threshold: numeric threshold

    Returns:
        list: filtered events
    """
    out = []
    for e in events or []:
        score = e.get('score', 0) if isinstance(e, dict) else 0
        if score >= threshold:
            out.append(e)
    return out
