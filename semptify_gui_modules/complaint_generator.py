"""Placeholder module extracted from scaffold: complaint_generator
This file is intentionally minimal. Implement module logic inside this package.
"""

def generate_complaint(data):
    """Return a simple complaint text for demonstration/testing."""
    name = data.get("name", "Unknown")
    issue = data.get("issue", "No issue provided")
    return f"Complaint for {name}: {issue}"
