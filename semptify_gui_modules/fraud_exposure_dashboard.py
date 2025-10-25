"""Fraud exposure dashboard stub.

Provides functions to summarize potential fraud indicators. Replace with real logic.
"""

def summarize_fraud(records, limit=10):
    """Return a short summary for a list of records.

    Args:
        records: iterable of record dicts
        limit: int number of items to include in the sample

    Returns:
        dict: {count, sample}
    """
    records = list(records) if records is not None else []
    sample = records[:limit]
    return {"count": len(records), "sample": sample}
