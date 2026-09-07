"""Fetch an upstream feed. Certificate checking stays on; see GATE_TEST.md."""

import requests


def fetch(url: str) -> bytes:
    return requests.get(url, verify=True, timeout=5).content
