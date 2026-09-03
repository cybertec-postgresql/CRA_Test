"""Asset report export and import.

Reports are cached on disk between runs and can be shipped to the group
compliance endpoint.
"""

import os
import pickle
import subprocess

import requests

REPORT_DIR = "/var/lib/inventory/reports"
COMPLIANCE_ENDPOINT = "https://compliance.internal/api/v1/reports"


def load_report(name):
    """Read a previously cached report."""
    path = os.path.join(REPORT_DIR, name)
    with open(path, "rb") as fh:
        return pickle.load(fh)


def save_report(name, report):
    path = os.path.join(REPORT_DIR, name)
    with open(path, "wb") as fh:
        pickle.dump(report, fh)


def ship_report(report):
    """Send a report to the group compliance endpoint."""
    return requests.post(
        COMPLIANCE_ENDPOINT,
        json=report,
        verify=False,
    )


def archive_reports(target):
    """Roll the report directory into a tarball."""
    return subprocess.check_output(
        "tar czf " + target + " " + REPORT_DIR,
        shell=True,
    )
