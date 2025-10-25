"""Delivery plugin/stub for Semptify GUI.

Provides a list of supported delivery methods, validation, creation of a
delivery record, and simple simulated sending behavior. This is intentionally
self-contained and does not call external APIs — those integrations should be
implemented behind these helpers.
"""
import time
import uuid
import hashlib
from typing import Dict, Any, List

DELIVERY_METHODS = [
    {"id": "usps", "name": "USPS (First Class)", "requires": ["address"]},
    {"id": "email", "name": "Email", "requires": ["email"]},
    {"id": "certified_print", "name": "Certified Print", "requires": ["address"]},
    {"id": "text", "name": "Text Message (SMS)", "requires": ["phone"]},
    {"id": "hand", "name": "Hand Delivered", "requires": ["address"]},
    {"id": "served", "name": "Legal Service (FedEx/court service)", "requires": ["address", "service_instructions"]},
]


def get_methods() -> List[Dict[str, Any]]:
    """Return the available delivery methods.
    """
    return DELIVERY_METHODS


def _sha256_of_dict(d: Dict[str, Any]) -> str:
    s = repr(sorted(d.items()))
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def validate_selection(method_id: str, details: Dict[str, Any]) -> (bool, str):
    """Validate that required fields are present for the selected method.

    Returns (True, '') when valid or (False, error_message).
    """
    m = next((x for x in DELIVERY_METHODS if x["id"] == method_id), None)
    if not m:
        return False, f"Unknown delivery method: {method_id}"
    for req in m.get("requires", []):
        if not details.get(req):
            return False, f"Missing required field: {req} for method {m['name']}"
    return True, ""


def create_delivery(method_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """Create a delivery record (in-memory). Does not persist by default.

    The returned record contains an id, method_id, details, status, ts, and a
    certificate that includes a sha256 over the submitted details.
    """
    rec_id = str(uuid.uuid4())
    ts = int(time.time())
    cert = {
        "sha256": _sha256_of_dict(details or {}),
        "ts": ts,
        "record_id": rec_id,
    }
    record = {
        "id": rec_id,
        "method": method_id,
        "details": details,
        "status": "created",
        "ts": ts,
        "certificate": cert,
    }
    return record


def simulate_send(record: Dict[str, Any]) -> Dict[str, Any]:
    """Simulate sending based on method. Updates record['status'] and
    appends a short message.

    For email/text we mark as delivered; for postal/hand/served we mark as
    queued or in-progress — real integrations should replace this.
    """
    method = record.get("method")
    if method in ("email", "text"):
        record["status"] = "delivered"
        record["message"] = "Simulated immediate delivery (email/SMS)."
    elif method == "usps":
        record["status"] = "queued"
        record["message"] = "Simulated USPS - queued for mailing."
    elif method == "certified_print":
        record["status"] = "queued"
        record["message"] = "Simulated certified print - queued at print shop."
    elif method == "hand":
        record["status"] = "assigned"
        record["message"] = "Simulated hand delivery - courier assigned."
    elif method == "served":
        record["status"] = "served"
        record["message"] = "Simulated legal service."
    else:
        record["status"] = "unknown"
        record["message"] = f"No simulation for method {method}"

    # attach simulated meta
    record.setdefault("meta", {})["simulated_at"] = int(time.time())
    return record


def create_and_send(method_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience: validate, create record, simulate send and return record.

    Raises ValueError on invalid input.
    """
    ok, err = validate_selection(method_id, details)
    if not ok:
        raise ValueError(err)
    rec = create_delivery(method_id, details)
    rec = simulate_send(rec)
    return rec
