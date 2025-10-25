"""License disruption tracker stub.

Tracks license statuses and reports potential disruptions.
"""

def check_license_status(licenses):
    """Return a map of license id -> status (placeholder).

    Args:
        licenses: iterable of license dicts with 'id' and 'expires' keys

    Returns:
        dict: mapping id to status string
    """
    out = {}
    for l in licenses or []:
        lid = l.get('id', 'unknown')
        out[lid] = 'ok' if not l.get('expires') else 'unknown'
    return out
