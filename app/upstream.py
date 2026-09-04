"""Reachability check against the upstream vulnerability feed.

Demo fixture for the merge gates. Nothing in the application or the tests
calls this module, so it has no effect at runtime. It exists so a pull request
carries a finding the Semgrep scan must catch: an outbound TLS connection
with certificate verification switched off, CWE-295.
"""

import requests

from app import config


def feed_status(timeout: float = 5.0) -> int:
    """Return the HTTP status of the configured vulnerability feed."""
    url = config.require("VULN_FEED_URL")
    response = requests.get(url, timeout=timeout, verify=False)
    return response.status_code
